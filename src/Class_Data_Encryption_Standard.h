#ifndef CLASS_DATA_ENCRYPTION_STANDARD_H
#define CLASS_DATA_ENCRYPTION_STANDARD_H

#include <stdint.h> /* uint8_t */
#include <stdbool.h>



/*============================================================================*/
/* Class */
/*============================================================================*/
typedef uint8_t T_DES_SUBKEY[6];
typedef struct {
    T_DES_SUBKEY subkeys[16];
} Class_Data_Encryption_Standard;
	
    
/*============================================================================*/
/* Public methods */
/*============================================================================*/
bool DES__Set_New_Key( 
    Class_Data_Encryption_Standard* Me,
    const uint8_t* key );

void DES__Cipher_Message(
    const Class_Data_Encryption_Standard* Me,
    const uint8_t* message,
    uint8_t* ciphered_message );
		
void DES__Decipher_Message(
    const Class_Data_Encryption_Standard* Me,
    const uint8_t* ciphered_message,
    uint8_t* deciphered_message );

#endif