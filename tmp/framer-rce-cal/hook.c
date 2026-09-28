#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <pthread.h>
#include <libavutil/buffer.h>

static __thread int in_hook;
static pthread_mutex_t mu=PTHREAD_MUTEX_INITIALIZER;

static void logline(const char *tag, void *a, void *b, void *c, size_t n, void *d, void *e){
  if(in_hook) return;
  in_hook=1;
  pthread_mutex_lock(&mu);
  fprintf(stderr,"CAL %s a=%p b=%p c=%p n=%zu d=%p e=%p\n",tag,a,b,c,n,d,e);
  fflush(stderr);
  pthread_mutex_unlock(&mu);
  in_hook=0;
}

AVBufferRef *av_buffer_alloc(size_t size){
  static AVBufferRef *(*real)(size_t);
  if(!real) real=dlsym(RTLD_NEXT,"av_buffer_alloc");
  AVBufferRef *r=real(size);
  if(r && (size<=512 || size>=8000))
    logline("buf_alloc",r,r->buffer,r->data,r->size,NULL,NULL);
  return r;
}
AVBufferRef *av_buffer_allocz(size_t size){
  static AVBufferRef *(*real)(size_t);
  if(!real) real=dlsym(RTLD_NEXT,"av_buffer_allocz");
  AVBufferRef *r=real(size);
  if(r && (size<=512 || size>=8000))
    logline("buf_allocz",r,r->buffer,r->data,r->size,NULL,NULL);
  return r;
}
AVBufferRef *av_buffer_create(uint8_t *data,size_t size,void (*freecb)(void*,uint8_t*),void *opaque,int flags){
  static AVBufferRef *(*real)(uint8_t*,size_t,void(*)(void*,uint8_t*),void*,int);
  if(!real) real=dlsym(RTLD_NEXT,"av_buffer_create");
  AVBufferRef *r=real(data,size,freecb,opaque,flags);
  if(r && (size<=512 || size>=8000))
    logline("buf_create",r,r->buffer,data,size,(void*)freecb,opaque);
  return r;
}
AVBufferRef *av_buffer_pool_get(AVBufferPool *pool){
  static AVBufferRef *(*real)(AVBufferPool*);
  if(!real) real=dlsym(RTLD_NEXT,"av_buffer_pool_get");
  AVBufferRef *r=real(pool);
  if(r && (r->size<=512 || r->size>=8000))
    logline("pool_get",pool,r,r->buffer,r->size,r->data,NULL);
  return r;
}
void av_buffer_unref(AVBufferRef **pr){
  static void (*real)(AVBufferRef**);
  if(!real) real=dlsym(RTLD_NEXT,"av_buffer_unref");
  if(pr && *pr){
    AVBufferRef *r=*pr;
    if(r->size<=512 || r->size>=8000)
      logline("buf_unref",r,r->buffer,r->data,r->size,NULL,NULL);
  }
  real(pr);
}

int posix_memalign(void **memptr,size_t align,size_t size){
  static int (*real)(void**,size_t,size_t);
  if(!real) real=dlsym(RTLD_NEXT,"posix_memalign");
  int rc=real(memptr,align,size);
  if(!rc && (size<=512 || size>=8000))
    logline("pmem",*memptr,(void*)align,NULL,size,NULL,NULL);
  return rc;
}

void free(void *p){
  static void (*real)(void*);
  if(!real) real=dlsym(RTLD_NEXT,"free");
  if(!in_hook && p) logline("free",p,NULL,NULL,0,NULL,NULL);
  real(p);
}
