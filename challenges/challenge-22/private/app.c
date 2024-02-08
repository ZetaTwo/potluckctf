#include "uart.h"
#include <string.h>
#define UICR_CUSTOMER ((void *)0x10001080)

long strtol(const char *restrict str, char **restrict endptr, int base);

void print_flag()
{
    char flag[32];
    uint32_t *uicr_cust = UICR_CUSTOMER;
    for (int i = 0; i < 8; i++)
    {
        *((int32_t *)&flag[i << 2]) = uicr_cust[i];
    }
    uart_puts(flag);
}

char board[9] = {0};

void print_board()
{
    uart_puts("  0 1 2\n +-+-+-+");
    for (int j = 0; j < 3; j++)
    {
        uart_putc(j+'0');
        uart_putc('|');
        for (int i = 0; i < 3; i++)
        {
            uart_putc(board[j * 3 + i]);
            uart_putc('|');
        }
        uart_putc(j+'0');
        uart_puts("\n +-+-+-+");
    }
    uart_puts("  0 1 2");
}

uint32_t check_win(char player)
{
    unsigned diag_1 = 0;
    unsigned diag_2 = 0;
    for (unsigned int i = 0; i < 3; i++)
    {
        unsigned row_count = 0;
        unsigned col_count = 0;
        for (unsigned int j = 0; j < 3; j++)
        {
            if (board[j * 3 + i] == player)
                row_count++;
            if (board[i * 3 + j] == player)
                col_count++;
        }
        if ((row_count == 3) || (col_count == 3))
            return 1;

        if (board[i * 3 + i] == player)
            diag_1++;
        if (board[i * 3 + 2 - i] == player)
            diag_2++;
    }

    if ((diag_1 == 3) || (diag_2 == 3))
        return 1;

    return 0;
}

uint32_t your_move()
{
    uart_puts("Your move. x,y?");
    char buf[5];
    uart_gets(buf, 5);
    char *input = buf;
    char *x_s = strsep(&input, ",");
    if (x_s == NULL)
    {
        uart_puts("Shenanigans!");
        return 1;
    }
    char *y_s = strsep(&input, ",");
    if (y_s == NULL)
    {
        uart_puts("Shenanigans!");
        return 1;
    }
    uint8_t x = strtol(x_s, NULL, 10);
    uint8_t y = strtol(y_s, NULL, 10);

    if ((x > 2) || (y > 2) || (board[y * 3 + x] != ' '))
    {
        uart_puts("Shenanigans!");
        return 1;
    }

    board[y * 3 + x] = 'X';

    return 0;
}

#define OPPOSITE(x) (x == 'X' ? 'O' : 'X')
uint32_t win_or_block(char player)
{
    unsigned diag_1 = 0;
    unsigned diag_2 = 0;
    for (unsigned int i = 0; i < 3; i++)
    {
        unsigned row_count = 0;
        unsigned col_count = 0;
        for (unsigned int j = 0; j < 3; j++)
        {
            if (board[i * 3 + j] == player)
                row_count++;
            if (board[i * 3 + j] == OPPOSITE(player))
                row_count--;
            if (board[j * 3 + i] == player)
                col_count++;
            if (board[j * 3 + i] == OPPOSITE(player))
                col_count--;
        }
        if (row_count == 2)
        {
            for (unsigned int j = 0; j < 3; j++)
            {
                if (board[i * 3 + j] != ' ')
                    continue;
                board[i * 3 + j] = 'O';
                return 1;
            }
        }
        if (col_count == 2)
        {
            for (unsigned int j = 0; j < 3; j++)
            {
                if (board[j * 3 + i] != ' ')
                    continue;
                board[j * 3 + i] = 'O';
                return 1;
            }
        }

        if (board[i * 3 + i] == player)
            diag_1++;
        if (board[i * 3 + i] == OPPOSITE(player))
            diag_1--;
        if (board[i * 3 + 2 - i] == player)
            diag_2++;
        if (board[i * 3 + 2 - i] == OPPOSITE(player))
            diag_2--;
    }
    if (diag_1 == 2)
    {
        for (unsigned int i = 0; i < 3; i++)
        {
            if (board[i * 3 + i] != ' ')
                continue;
            board[i * 3 + i] = 'O';
            return 1;
        }
    }
    if (diag_2 == 2)
    {
        for (unsigned int i = 0; i < 3; i++)
        {
            if (board[i * 3 + 2 - i] != ' ')
                continue;
            board[i * 3 + 2 - i] = 'O';
            return 1;
        }
    }

    return 0;
}

uint32_t play_center()
{
    if (board[4] == ' ')
    {
        board[4] = 'O';
        return 1;
    }
    return 0;
}

uint32_t play_opposite_corner()
{
    if (board[0] == 'X' && board[8] == ' ')
    {
        board[8] = 'O';
        return 1;
    }
    if (board[2] == 'X' && board[6] == ' ')
    {
        board[6] = 'O';
        return 1;
    }
    if (board[0] == ' ' && board[8] == 'X')
    {
        board[0] = 'O';
        return 1;
    }
    if (board[2] == ' ' && board[6] == 'X')
    {
        board[2] = 'O';
        return 1;
    }
    return 0;
}

uint32_t play_corner()
{
    for (int i = 0; i < 9; i += 2)
    {
        if (i == 4)
            continue;

        if (board[i] == ' ')
        {
            board[i] = 'O';
            return 1;
        }
    }
    return 0;
}

uint32_t play_side()
{
    for (int i = 1; i < 8; i += 2)
    {
        if (board[i] == ' ')
        {
            board[i] = 'O';
            return 1;
        }
    }
    return 0;
}

/*
  0 1 2
  3 4 5
  6 7 8
*/
uint32_t play_fork(char player)
{
    unsigned row_count[3] = {0};
    unsigned col_count[3] = {0};
    char row_owner[3] = {' '};
    char col_owner[3] = {' '};
    unsigned diag_1 = 0;
    unsigned diag_2 = 0;
    char diag_1_owner = ' ';
    char diag_2_owner = ' ';

    for (unsigned int i = 0; i < 3; i++)
    {
        for (unsigned int j = 0; j < 3; j++)
        {
            if (board[i * 3 + j] == ' ')
                row_count[i]++;
            else
                row_owner[i] = board[i*3+j];
            if (board[j * 3 + i] == ' ')
                col_count[i]++;
            else
                row_owner[i] = board[j*3+i];
        }

        if (board[i * 3 + i] == ' ')
            diag_1++;
        else
            diag_1_owner = board[i * 3 + i];
        if (board[i * 3 + 2 - i] == ' ')
            diag_2++;
        else
            diag_1_owner = board[i * 3 + 2 - i];
    }

    if ((player == 'X') && (board[4] == 'O')) {
        // blocking, and we hold the center.
        if ((board[0] == 'X') && (board[8] == 'X')) {
            // They have the corners on the diagonal.
            if ((row_count[0] == 2) && (col_count[2] == 2)) {
                // block in upper right corner
                if (row_count[1] == 2) {
                    board[5] = 'O';
                    return 1;
                }
                if (col_count[1] == 2) {
                    board[1] = 'O';
                    return 1;
                }
            }
            if ((row_count[2] == 2) && (col_count[0] == 2)) {
                // block in bottom left corner
                if (row_count[1] == 2) {
                    board[3] = 'O';
                    return 1;
                }
                if (col_count[1] == 2) {
                    board[7] = 'O';
                    return 1;
                }
            }
        }

        if ((board[2] == 'X') && (board[6] == 'X')) {
            // They have the corners on the off-diagonal.
            if ((row_count[0] == 2) && (col_count[0] == 2)) {
                if (row_count[1] == 2) {
                    board[3] = 'O';
                    return 1;
                }
                if (col_count[1] == 2) {
                    board[1] = 'O';
                    return 1;
                }
            }
            if ((row_count[2] == 2) && (col_count[2] == 2)) {
                if (row_count[1] == 2) {
                    board[5] = 'O';
                    return 1;
                }
                if (col_count[1] == 2) {
                    board[7] = 'O';
                    return 1;
                }
            }
        }
    }

    for (int i = 0; i < 3; i++) {
        if ((row_count[i] == 2) && (col_count[i] == 2)
            && (col_owner[i] == player) && (row_owner[i] == player)
            && (board[i*3+i] == ' '))
        {
            board[i*3+i] = 'O';
            return 1;
        }
        if ((row_count[i] == 2) && (col_count[2-i] == 2)
            && (row_owner[i] == player) && (col_owner[2-i] == player)
            && (board[i*3+2-i] == ' '))
        {
            board[i*3+2-i] = 'O';
            return 1;
        }
        if ((diag_1 == 2) && (diag_1_owner == player) 
            && (((col_count[i] == 2) && (col_owner[i] == player))
                || ((row_count[i] == 2) && (row_owner[i] == player)))
            && (board[i*3+i] == ' '))
        {
            board[i*3+i] = 'O';
            return 1;
        }
        if ((diag_2 == 2) && (diag_2_owner == player) 
            && (((col_count[i] == 2) && (col_owner[i] == player))
                || ((row_count[i] == 2) && (row_owner[i] == player)))
            && (board[i*3+2-i] == ' '))
        {
            board[i*3+2-i] = 'O';
            return 1;
        }
    }

    return 0;
}

void my_move()
{
    // 1
    if (win_or_block('O'))
        return;
    // 2
    if (win_or_block('X'))
        return;
    // 3
    if (play_fork('O'))
        return;
    // 4
    if (play_fork('X'))
        return;
    // 5
    if (play_center())
        return;
    // 6
    if (play_opposite_corner())
        return;
    // 7
    if (play_corner())
        return;
    // 8
    play_side();
}

void play()
{
    memset(board, ' ', 9);
    uint32_t moves = 0;
    while (1)
    {
        print_board();
        if (your_move()) 
            continue;
        print_board();
        if (check_win('X'))
        {
            uart_puts("You win! Have a flag:");
            print_flag();
            break;
        }
        if (moves++ == 4) {
            uart_puts(
                "Looks like nobody won. Better luck next time!\n"
                "How about we share the flag. You get the first part:"
            );
            uart_puts("potluck{");
            break;
        }
        uart_puts("My move:");
        my_move();
        if (check_win('O'))
        {
            print_board();
            uart_puts("You lose. No flag for you. Try again.");
            break;
        }
    }
}

void main()
{
    const uint32_t bits[] = {
        0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFB, 0xFFFFFFF7,
        0xFFFFFFEF, 0xFFFFFFDF, 0xFFFFFFBF, 0xFFFFFF7F,
        0xFFFFFEFF, 0xFFFFFDFF, 0xFFFFFBFF, 0xFFFFF7FF,
        0xFFFFEFFF, 0xFFFFDFFF, 0xFFFFBFFF, 0xFFFF7FFF,
        0xFFFEFFFF, 0xFFFDFFFF, 0xFFFBFFFF, 0xFFF7FFFF,
        0xFFEFFFFF, 0xFFDFFFFF, 0xFFBFFFFF, 0xFF7FFFFF,
        0xFEFFFFFF, 0xFDFFFFFF, 0xFBFFFFFF, 0xF7FFFFFF,
        0xEFFFFFFF, 0xDFFFFFFF, 0xBFFFFFFF, 0x7FFFFFFF,
    };
    uart_init();
    uart_puts("Shall we play a game?\n");
    while (1)
    {
        play();
    }
}
