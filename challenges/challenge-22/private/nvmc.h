#ifndef __NVMC_H__
#define __NVMC_H__

void nvmc_erase_all();
void nvmc_erase_page(void* addr);
void nvmc_erase_uicr();
void nvmc_write(void* dest, void* src, size_t length);

#endif