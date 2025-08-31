#pragma once

#include <stdint.h>
#include <stddef.h>

size_t
get_td_hob_size();

int
create_td_hob(uint8_t *dest, size_t dest_len);

int
create_td_hob_from_ovmf(uint8_t** dest, size_t* dest_len, uint8_t* raw_ovmf_image, uint64_t raw_ovmf_image_size);

void
print_td_hob(uint8_t *data, size_t len);
