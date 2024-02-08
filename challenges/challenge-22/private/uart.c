#include <unistd.h>
#include "nvic.h"

struct __attribute__((packed)) UART {
    uint32_t TASKS_STARTRX; // 0x000
    uint32_t TASKS_STOPRX;  // 0x004
    uint32_t TASKS_STARTTX; // 0x008 Start UART transmitter
    uint32_t TASKS_STOPTX;  // 0x00C Stop UART transmitter
    char padding0[0xc];
    uint32_t TASKS_SUSPEND; // 0x01C Suspend UART
    char padding1[0xe0];
    uint32_t EVENTS_CTS;    // 0x100 CTS is activated (set low). Clear To Send.
    uint32_t EVENTS_NCTS;   // 0x104 CTS is deactivated (set high). Not Clear To Send.
    uint32_t EVENTS_RXDRDY; // 0x108 Data received in RXD
    char padding2[0x10];
    uint32_t EVENTS_TXDRDY; // 0x11C Data sent from TXD
    char padding3[0x4];
    uint32_t EVENTS_ERROR;  // 0x124 Error detected
    char padding4[0x1c];
    uint32_t EVENTS_RXTO;   // 0x144 Receiver timeout
    char padding5[0xb8];
    uint32_t SHORTS;        // 0x200 Shortcuts between local events and tasks
    char padding6[0x100];
    uint32_t INTENSET;      // 0x304 Enable interrupt
    uint32_t INTENCLR;      // 0x308 Disable interrupt
    char padding7[0x174];
    uint32_t ERRORSRC;      // 0x480 Error source
    char padding8[0x7c];
    uint32_t ENABLE;        // 0x500 Enable UART
    char padding9[4];
    uint32_t PSEL_RTS;      // 0x508 Pin Select for RTS
    uint32_t PSEL_TXD;      // 0x50C Pin Select for TXD
    uint32_t PSEL_CTS;      // 0x510 Pin Select for CTS
    uint32_t PSEL_RXD;      // 0x514 Pin Select for RXD
    uint32_t RXD;           // 0x518 RXD Register
    uint32_t TXD;           // 0x51C TXD Register
    char padding10[4];
    uint32_t BAUDRATE;      // 0x524 Baud rate
    char padding11[0x44];
    uint32_t CONFIG;        // 0x564 CONFIG
};

static volatile struct UART *const UART0 = (struct UART*) 0x40002000;

char uart_rx_buffer[0x1000];
size_t uart_rx_write_offset = 0;
size_t uart_rx_read_offset = 0;

void uart_init() {
    UART0->BAUDRATE = 0x01D60000; // 11520
    UART0->CONFIG = 0; // 8n1
    UART0->ENABLE = 4;
    UART0->TASKS_STARTTX = 1;
    UART0->TASKS_STARTRX = 1;
    UART0->INTENSET = 0b100; // RXRDY triggers interrupt.
    nvic_enable_irq(2);
    nvic_set_priority(2, 0);
}

void uart_putc(char c) {
    UART0->TXD = (uint32_t) c;
    while (UART0->EVENTS_TXDRDY == 0) { }
    UART0->EVENTS_TXDRDY = 0;
}

void uart_puts(char* s) {
    char c;
    while (c = *(s++)) {
        uart_putc(c);
    }
    uart_putc('\n');
}

char uart_getc() {
    while((uart_rx_write_offset - uart_rx_read_offset) % sizeof(uart_rx_buffer) == 0) {};
    char c = uart_rx_buffer[uart_rx_read_offset++ % sizeof(uart_rx_buffer)];
    return c;
}

void uart_gets(char *dest, size_t n) {
    size_t i = 0;
    while (i < n - 1) {
        char c = uart_getc();
        uart_putc(c);
        dest[i] = c;
        if ((c == '\r') || (c == '\n')) {
            uart_putc('\n');
            break;
        }
        i++;
    }
    dest[i++] = '\0';
}

void uart_read(char *const dest, size_t n) {
    for (size_t i = 0; i < n; i++) {
        dest[i] = uart_getc();
    }
}

void uart_write(char *const src, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uart_putc(src[i]);
    }
}


void UARTE0_UART0_IRQHandler() {
    nvic_disable_irq(2);
    UART0->EVENTS_RXDRDY = 0;
    char c = (char) UART0->RXD;
    uart_rx_buffer[uart_rx_write_offset++ % sizeof(uart_rx_buffer)] = c;
    if (((uart_rx_write_offset - uart_rx_read_offset) % sizeof(uart_rx_buffer)) == sizeof(uart_rx_buffer) - 1) {
        uart_puts("UART OVERRUN!\r\n");
    }
    nvic_enable_irq(2);
}
