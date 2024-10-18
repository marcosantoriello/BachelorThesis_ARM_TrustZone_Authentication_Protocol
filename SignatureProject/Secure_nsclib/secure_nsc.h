/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file    Secure_nsclib/secure_nsc.h
  * @author  MCD Application Team
  * @brief   Header for secure non-secure callable APIs list
  ******************************************************************************
    * @attention
  *
  * Copyright (c) 2024 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */

/* USER CODE BEGIN Non_Secure_CallLib_h */
/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef SECURE_NSC_H
#define SECURE_NSC_H

/* Includes ------------------------------------------------------------------*/
#include <stdint.h>

/* Exported types ------------------------------------------------------------*/
/**
  * @brief  non-secure callback ID enumeration definition
  */
typedef enum
{
  SECURE_FAULT_CB_ID     = 0x00U, /*!< System secure fault callback ID */
  GTZC_ERROR_CB_ID       = 0x01U  /*!< GTZC secure error callback ID */
} SECURE_CallbackIDTypeDef;

/* Exported constants --------------------------------------------------------*/
/* Exported macro ------------------------------------------------------------*/
#ifndef WOLFSSL_TYPES
     #ifndef byte
         typedef unsigned char  byte;
         typedef   signed char  sword8;
         typedef unsigned char  word8;
     #endif
     #ifdef WC_16BIT_CPU
         typedef          int   sword16;
         typedef unsigned int   word16;
         typedef          long  sword32;
         typedef unsigned long  word32;
     #else
         typedef          short sword16;
         typedef unsigned short word16;
         typedef          int   sword32;
         typedef unsigned int   word32;
     #endif
     typedef byte           word24[3];
 #endif
/* Exported functions ------------------------------------------------------- */
void SECURE_RegisterCallback(SECURE_CallbackIDTypeDef CallbackId, void *func);
void SECURE_get_rsa_pk(byte *out_public_key, uint32_t *out_key_size);
void SECURE_rsa_encrypt(byte *input, word32 inputSz, byte *output, word32 *outputSz);
void SECURE_rsa_decrypt(byte *input, word32 inputSz, byte *output, word32 *outputSz);
void SECURE_generate_rsa_keys(void);
void SECURE_rsa_sign(byte *input, word32 inputSz, byte *output, word32 *outputSz);
void SECURE_rsa_verify_signature(byte *input, word32 inputSz, byte* rsa_sig_2048, uint8_t *status);
void SECURE_get_enc_secret_token(byte *out_token);
#endif /* SECURE_NSC_H */
/* USER CODE END Non_Secure_CallLib_h */

