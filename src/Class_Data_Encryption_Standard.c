#include "Class_Data_Encryption_Standard.h"

#include <string.h> /* memcpy */
#include "Memory_Mapping.h"
#include "Bits_Management.h"

enum {CIPHER, DECIPHER};
	
static const PROGMEM uint8_t PC1[56] = {
    56, 48, 40, 32, 24, 16,  8,
     0, 57, 49, 41, 33, 25, 17,
     9,  1, 58, 50, 42, 34, 26,
    18, 10,  2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,
     6, 61, 53, 45, 37, 29, 21,
    13,  5, 60, 52, 44, 36, 28,
    20, 12,  4, 27, 19, 11,  3
};

static const PROGMEM uint8_t PC2[48] = {
    13, 16, 10, 23,  0,  4,
     2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7,
    15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54,
    29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52,
    45, 41, 49, 35, 28, 31
};

static const PROGMEM uint8_t IP[64] = {
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
    56, 48, 40, 32, 24, 16,  8,  0,
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6
};

static const PROGMEM uint8_t FP[64] = {
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
    32,  0, 40,  8, 48, 16, 56, 24
};

static const PROGMEM uint8_t EI[48] = {
    31,  0,  1,  2,  3,  4,
     3,  4,  5,  6,  7,  8,
     7,  8,  9, 10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31,  0
};

/* S boxes */
static const PROGMEM uint8_t SI[8][4][16] = {
    /* S1 */
    {{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
     { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
     { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
     {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}},

    /* S2 */
    {{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
     {3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
     {0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
     {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}},

    /* S3 */
    {{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
     {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
     {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
     { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}},

    /* S4 */
    {{ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
     {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
     {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
     { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}},

    /* S5 */
    {{ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
     {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
     { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
     {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}},

    /* S6 */
    {{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
     {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
     { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
     { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}},

    /* S7 */
    {{ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
     {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
     { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
     { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}},

    /* S8 */
    {{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
     { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
     { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
     { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}}
};

static const PROGMEM uint8_t P[32] = {
    15,  6, 19, 20,
    28, 11, 27, 16,
     0, 14, 22, 25,
     4, 17, 30,  9,
     1,  7, 23, 13,
    31, 26,  2,  8,
    18, 12, 29,  5,
    21, 10,  3, 24
};


/*============================================================================*/
/* Private methods declaration */
/*============================================================================*/
static void Execute_Algorithm(
    const Class_Data_Encryption_Standard* Me,
    const uint8_t* message_in,
    uint8_t* message_out,
    int mode );
static void Permute_Bits_Left( uint8_t* const block );



/*============================================================================*/
/* Public methods */
/*============================================================================*/
bool DES__Set_New_Key( Class_Data_Encryption_Standard* Me, const uint8_t* key )
{
    uint8_t block_56_bits[7] = {0};
    int key_idx = 0;
	int byte_idx = 0;
	bool is_key_valid = true;

	/* Check key */
	for( byte_idx=0 ; byte_idx<=7 ; byte_idx++ )
	{
		if( false == Is_Byte_Even( key[byte_idx] ) )
		{
			is_key_valid = false;
		}
	}

    Permute_Bits( key, 56, block_56_bits, PC1 );
    for( key_idx=0 ; key_idx<=15 ; key_idx++ )
    {
        if( key_idx==0 || key_idx==1 || key_idx==8 || key_idx==15 )
        {
            /* Left shift once */
            Permute_Bits_Left( block_56_bits );
        }
        else
        {
            /* Left shift twice */
            Permute_Bits_Left( block_56_bits );
            Permute_Bits_Left( block_56_bits );
        }
        Permute_Bits( block_56_bits, 48, (Me->subkeys)[key_idx], PC2 );
    }
	
	return is_key_valid;
}
/*----------------------------------------------------------------------------*/
void DES__Cipher_Message(
    const Class_Data_Encryption_Standard* Me,
    const uint8_t* message,
    uint8_t* ciphered_message )
{
    Execute_Algorithm( Me, message, ciphered_message, CIPHER );
}
/*----------------------------------------------------------------------------*/
void DES__Decipher_Message(
    const Class_Data_Encryption_Standard* Me,
    const uint8_t* ciphered_message,
    uint8_t* deciphered_message )
{
    Execute_Algorithm( Me, ciphered_message, deciphered_message, DECIPHER );
}


/*============================================================================*/
/* Private methods definition */
/*============================================================================*/
static void Execute_Algorithm(
    const Class_Data_Encryption_Standard* Me,
    const uint8_t* message_in,
    uint8_t* message_out,
    int mode )
{
    uint8_t message_copy[8] = {0};
    uint8_t* left = NULL;
    uint8_t* right = NULL;
    uint8_t right_copy[4] = {0};
    uint8_t right_tmp[4] = {0};
    uint8_t right_exp[6] = {0};
    uint8_t box_value = 0;
    int iteration = 0;
    int byte_idx = 0;
    uint8_t box_idx = 0;
    int b_0, b_1, b_2, b_3, b_4, b_5;
    int row, column;

    memcpy( message_copy, message_in, 8 );

    /* Initial permutation  */
    Permute_Bits( message_in, 64, message_copy, IP );

    /* Split in two blocks */
    left = message_copy;
    right = &(message_copy[4]);

    /* Copy right block */
    memcpy( right_copy, right, 4 );

    for( iteration=0 ; iteration<=15 ; iteration++ )
    {
        /* Expansion */
        Permute_Bits( right, 48, right_exp, EI );

        if( mode==CIPHER )
        {
            for( byte_idx=0 ; byte_idx<6 ; byte_idx++ )
            {
                right_exp[byte_idx]^=((Me->subkeys)[iteration][byte_idx]);
            }
        }
        else if( mode==DECIPHER )
        {
            for( byte_idx=0 ; byte_idx<6 ; byte_idx++ )
            {
                right_exp[byte_idx]^=((Me->subkeys)[15-iteration][byte_idx]);
            }
        }
        else
        {
            /* error */
        }

        /* Selection function */
        memset( right_tmp, 0, 4 );
        for( box_idx=0 ; box_idx <=7 ; box_idx++ )
        {
            uint8_t shift;
            shift = 6*box_idx;
            b_0 = Test_Bit_Block( right_exp, 0 + shift );
            b_1 = Test_Bit_Block( right_exp, 1 + shift );
            b_2 = Test_Bit_Block( right_exp, 2 + shift );
            b_3 = Test_Bit_Block( right_exp, 3 + shift );
            b_4 = Test_Bit_Block( right_exp, 4 + shift );
            b_5 = Test_Bit_Block( right_exp, 5 + shift );
            row = b_0*2 + b_5;
            column = b_1*8 + b_2*4 + b_3*2 + b_4;
            box_value = pgm_read_byte(&(SI[box_idx][row][column]));
            shift = 4*box_idx;
            if( (box_value&0x08) )
            {
                Set_Bit_Block( right_tmp, 0 + shift );
            }
            if( (box_value&0x04) )
            {
                Set_Bit_Block( right_tmp, 1 + shift );
            }
            if( (box_value&0x02) )
            {
                Set_Bit_Block( right_tmp, 2 + shift );
            }
            if( (box_value&0x01) )
            {
                Set_Bit_Block( right_tmp, 3 + shift );
            }
        }

        /* Permutation */
        Permute_Bits( right_tmp, 32, right, P );

        for( byte_idx=0 ; byte_idx<=3 ; byte_idx++ )
        {
            right[byte_idx] ^= left[byte_idx];
            left[byte_idx] = right_copy[byte_idx];
            right_copy[byte_idx] = right[byte_idx];
        }
    }
    /* Final permutation */
    memcpy( right, left, 4);
    memcpy( left, right_copy, 4);
    Permute_Bits( message_copy, 64, message_out, FP );
}
/*----------------------------------------------------------------------------*/
static void Permute_Bits_Left( uint8_t* block_56_bits )
{
    int bit_0 = 0;
    int bit_28 = 0;
    uint8_t bit_index = 0;

    bit_0 = Test_Bit_Block( block_56_bits, 0 );
    bit_28 = Test_Bit_Block( block_56_bits, 28 );

    for( bit_index = 0; bit_index<=54 ; bit_index++ )
    {
        if( Test_Bit_Block( block_56_bits, bit_index+1 ) )
        {
            Set_Bit_Block( block_56_bits, bit_index );
        }
        else
        {
            Reset_Bit_Block( block_56_bits, bit_index );
        }
    }
    if( bit_0 )
    {
        Set_Bit_Block( block_56_bits, 27 );
    }
    else
    {
        Reset_Bit_Block( block_56_bits, 27 );
    }
    if( bit_28 )
    {
        Set_Bit_Block( block_56_bits, 55 );
    }
    else
    {
        Reset_Bit_Block( block_56_bits, 55 );
    }
}