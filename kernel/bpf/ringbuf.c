// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/err.h>
#include <linux/irq_work.h>
#include <linux/slab.h>
#include <linux/filter.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/kmemleak.h>
#include <uapi/linux/btf.h>

#define RINGBUF_CREATE_FLAG_MASK (BPF_F_NUMA_NODE)

struct bpf_ringbuf {
wait_queue_head_t waitq;
struct irq_work work;
u64 mask;
struct page **pages;
int nr_pages;
spinlock_t spinlock ____cacheline_aligned_in_smp;
unsigned long consumer_pos __attribute__((aligned(PAGE_SIZE)));
unsigned long producer_pos __attribute__((aligned(PAGE_SIZE)));
char data[] __attribute__((aligned(PAGE_SIZE)));
};

struct bpf_ringbuf_map {
struct bpf_map map;
struct bpf_ringbuf *rb;
};

static struct bpf_ringbuf *bpf_ringbuf_area_alloc(size_t data_sz, int numa_node)
{
const gfp_t flags = GFP_KERNEL | __GFP_RETRY_MAYFAIL | __GFP_NOWARN | __GFP_ZERO;
int nr_meta_pages = 2;
int nr_data_pages = data_sz >> PAGE_SHIFT;
int nr_pages = nr_meta_pages + nr_data_pages;
struct page **pages, *page;
struct bpf_ringbuf *rb;
size_t array_size;
int i;

array_size = (nr_meta_pages + 2 * nr_data_pages) * sizeof(*pages);
pages = bpf_map_area_alloc(array_size, numa_node);
if (!pages)
return NULL;

for (i = 0; i < nr_pages; i++) {
page = alloc_pages_node(numa_node, flags, 0);
if (!page) {
nr_pages = i;
goto err_free_pages;
}
pages[i] = page;
if (i >= nr_meta_pages)
pages[nr_data_pages + i] = page;
}

rb = vmap(pages, nr_meta_pages + 2 * nr_data_pages, VM_MAP | VM_USERMAP, PAGE_KERNEL);
if (rb) {
kmemleak_not_leak(pages);
rb->pages = pages;
rb->nr_pages = nr_pages;
return rb;
}

err_free_pages:
for (i = 0; i < nr_pages; i++)
__free_page(pages[i]);
bpf_map_area_free(pages);
return NULL;
}

static void bpf_ringbuf_area_free(struct bpf_ringbuf *rb)
{
struct page **pages = rb->pages;
int i;

vunmap(rb);
for (i = 0; i < rb->nr_pages; i++)
__free_page(pages[i]);
bpf_map_area_free(pages);
}

static struct bpf_ringbuf *bpf_ringbuf_alloc(size_t data_sz, int numa_node)
{
struct bpf_ringbuf *rb;

rb = bpf_ringbuf_area_alloc(data_sz, numa_node);
if (!rb)
return ERR_PTR(-ENOMEM);

spin_lock_init(&rb->spinlock);
init_waitqueue_head(&rb->waitq);
rb->mask = data_sz - 1;
rb->consumer_pos = 0;
rb->producer_pos = 0;
return rb;
}

static int ringbuf_map_alloc_check(union bpf_attr *attr)
{
if (attr->map_flags & ~RINGBUF_CREATE_FLAG_MASK ||
    attr->key_size || attr->value_size ||
    !is_power_of_2(attr->max_entries) ||
    !PAGE_ALIGNED(attr->max_entries))
return -EINVAL;
return 0;
}

static struct bpf_map *ringbuf_map_alloc(union bpf_attr *attr)
{
struct bpf_ringbuf_map *rb_map;

rb_map = bpf_map_area_alloc(sizeof(*rb_map), attr->numa_node);
if (!rb_map)
return ERR_PTR(-ENOMEM);

bpf_map_init_from_attr(&rb_map->map, attr);
rb_map->rb = bpf_ringbuf_alloc(attr->max_entries, rb_map->map.numa_node);
if (IS_ERR(rb_map->rb)) {
int err = PTR_ERR(rb_map->rb);
bpf_map_area_free(rb_map);
return ERR_PTR(err);
}
return &rb_map->map;
}

static void ringbuf_map_free(struct bpf_map *map)
{
struct bpf_ringbuf_map *rb_map = container_of(map, struct bpf_ringbuf_map, map);
bpf_ringbuf_area_free(rb_map->rb);
bpf_map_area_free(rb_map);
}

static void *ringbuf_map_lookup_elem(struct bpf_map *map, void *key)
{
return ERR_PTR(-ENOTSUPP);
}

static int ringbuf_map_update_elem(struct bpf_map *map, void *key, void *value, u64 flags)
{
return -ENOTSUPP;
}

static int ringbuf_map_delete_elem(struct bpf_map *map, void *key)
{
return -ENOTSUPP;
}

static int ringbuf_map_get_next_key(struct bpf_map *map, void *key, void *next_key)
{
return -ENOTSUPP;
}

static int ringbuf_map_mmap_kern(struct bpf_map *map, struct vm_area_struct *vma)
{
struct bpf_ringbuf_map *rb_map = container_of(map, struct bpf_ringbuf_map, map);

if (vma->vm_flags & VM_WRITE) {
if (vma->vm_pgoff != 0)
return -EPERM;
if (vma->vm_end - vma->vm_start != PAGE_SIZE)
return -EINVAL;
} else {
vma->vm_flags &= ~VM_MAYWRITE;
}
return remap_vmalloc_range(vma, rb_map->rb, vma->vm_pgoff + 1);
}

static unsigned long ringbuf_avail_data_sz(struct bpf_ringbuf *rb)
{
unsigned long cons_pos = smp_load_acquire(&rb->consumer_pos);
unsigned long prod_pos = smp_load_acquire(&rb->producer_pos);
return prod_pos - cons_pos;
}

static __poll_t ringbuf_map_poll_kern(struct bpf_map *map, struct file *filp, struct poll_table_struct *pts)
{
struct bpf_ringbuf_map *rb_map = container_of(map, struct bpf_ringbuf_map, map);
poll_wait(filp, &rb_map->rb->waitq, pts);
if (ringbuf_avail_data_sz(rb_map->rb))
return EPOLLIN | EPOLLRDNORM;
return 0;
}

const struct bpf_map_ops ringbuf_map_ops = {
.map_alloc_check = ringbuf_map_alloc_check,
.map_alloc = ringbuf_map_alloc,
.map_free = ringbuf_map_free,
.map_mmap = ringbuf_map_mmap_kern,
.map_poll = ringbuf_map_poll_kern,
.map_lookup_elem = ringbuf_map_lookup_elem,
.map_update_elem = ringbuf_map_update_elem,
.map_delete_elem = ringbuf_map_delete_elem,
.map_get_next_key = ringbuf_map_get_next_key,
};
