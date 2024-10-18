/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
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
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include <string.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define CHALLENGE_SIZE 128
#define SIGNATURE_SIZE 256
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

UART_HandleTypeDef huart1;

/* USER CODE BEGIN PV */

uint8_t rx_buffer[256];
uint16_t rx_length = 0;
uint8_t rx_data;        // byte received via interrupt
uint8_t signature_received = 0;
uint8_t auth_request_received = 0;
/*
 * Verification status is the result of the signature verification: 0 -> not verified, 1 -> verified
*/
uint8_t verification_status = 0;



byte publicKeyDer[4096];
uint32_t publicKeyDerSz;

byte encrypted[256];
word32 encryptedSz = sizeof(encrypted);
byte decrypted[384];
word32 decryptedSz = sizeof(decrypted);

uint8_t signature[256];
word32 signature_len;
char *challenge = "bOIBgdzTHZN3SlElS2ISu0Sn6oipMBvtLQZYaKoz24bdO4rLmbd5bfYDQnNYbFOfZ5XyCnDc5JebFkOALKihpKloQsH84ualOzNjsBBKXFu5JvCoeqCcZnZaHeT5hJxcWVXRvi08B06eQl3FbXvTrH3JqcGePLEC17QivhSQ3K9VOwePMFMl4sYuc8K3hZ4LyuIZJKCfFelxEOEmYLtxve4F7Yd3juOQ0cvmIRbPUcLAmac38ubCMtDeRRLdRh1B";
byte secret_token[256];
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
static void MX_GPIO_Init(void);
static void MX_RTC_Init(void);
static void MX_USART1_UART_Init(void);
/* USER CODE BEGIN PFP */

void print_hex(const unsigned char* data, size_t len);
int hex_to_bytes(const char* hex_str, unsigned char* byte_array, size_t byte_array_len);

/* Retargets the C library printf function to the USART. */
#include <stdio.h>
#ifdef __GNUC__
int __io_putchar(int ch)
#else
int fputc(int ch, FILE *f)
#endif
{
    HAL_UART_Transmit(&huart1, (uint8_t *)&ch, 1, 0xFFFF);

    return ch;
}
#ifdef __GNUC__
int _write(int file,char *ptr, int len)
{
    int DataIdx;
    for (DataIdx= 0; DataIdx< len; DataIdx++) {
        __io_putchar(*ptr++);
    }
    return len;
}
#endif

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/********************************** UTILITY FUNCTIONS ************************************/
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\r\n");
}

int hex_to_bytes(const char* hex_str, unsigned char* byte_array, size_t byte_array_len) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) {
        return -1;
    }

    if (hex_len / 2 > byte_array_len) {
        return -1;
    }

    for (size_t i = 0; i < hex_len; i += 2) {
        if (!isxdigit(hex_str[i]) || !isxdigit(hex_str[i + 1])) {
            return -1;
        }

        char byte_str[3] = { hex_str[i], hex_str[i + 1], '\0' };
        byte_array[i / 2] = (unsigned char)strtol(byte_str, NULL, 16);
    }

    return 0;
}

/************************************ USART FUNCITONS ********************************************/
//void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart){
//	static uint8_t idx = 0;
//
//	if (huart->Instance == USART1) {
//		// saving the received byte
//		if (rx_data != '\n') {
//			rx_buffer[idx++] = rx_data;
//		} else {
//			rx_buffer[idx] = '\0';
//			idx = 0;
//			if (auth_request_received) {
//				signature_received = 1;
//			} else if (!auth_request_received) {
//				auth_request_received = 1;
//			}
//		}
//
//		 HAL_UART_Receive_IT(&huart1, &rx_data, 1);
//	}
//
//}

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart) {
	static uint16_t idx = 0;

	if (huart->Instance == USART1) {
		if (idx < sizeof(rx_buffer)) {
			rx_buffer[idx++] = rx_data;
		}

		if (rx_data == '\n') {
			rx_length = idx;
			idx = 0;
			if (auth_request_received) {
				signature_received = 1;
			} else {
				auth_request_received = 1;
			}
		}

		HAL_UART_Receive_IT(&huart1, &rx_data, 1);
	}
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */
	/* Turn off buffers, so I/O occurs immediately */
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_RTC_Init();
  MX_USART1_UART_Init();
  /* USER CODE BEGIN 2 */

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

		if (!signature_received) {
			HAL_UART_Receive_IT(&huart1, &rx_data, 1);
			HAL_Delay(6000);

			HAL_UART_Transmit(&huart1, challenge, strlen(challenge),
					HAL_MAX_DELAY);

			HAL_UART_Receive_IT(&huart1, &rx_data, 1);
		}

		else {
			signature_len = sizeof(signature);

			if (rx_length == 256) {
				SECURE_rsa_verify_signature(challenge, strlen(challenge),
						rx_buffer, &verification_status);
				if (verification_status) {
					printf("Signature verified\n\r");
					SECURE_get_enc_secret_token(&secret_token);
					HAL_Delay(1000);
					HAL_UART_Transmit(&huart1, secret_token, strlen(secret_token),
										HAL_MAX_DELAY);

				} else {
					printf("Failure\r\n");
				}
				signature_received = 0;
				auth_request_received = 0;
			}

			HAL_UART_Receive_IT(&huart1, &rx_data, 1);
		}
    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief RTC Initialization Function
  * @param None
  * @retval None
  */
static void MX_RTC_Init(void)
{

  /* USER CODE BEGIN RTC_Init 0 */

  /* USER CODE END RTC_Init 0 */

  /* USER CODE BEGIN RTC_Init 1 */

  /* USER CODE END RTC_Init 1 */
  /* USER CODE BEGIN RTC_Init 2 */

  /* USER CODE END RTC_Init 2 */

}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
	huart1.Instance = USART1;
	huart1.Init.BaudRate = 115200;
	huart1.Init.WordLength = UART_WORDLENGTH_8B;
	huart1.Init.StopBits = UART_STOPBITS_1;
	huart1.Init.Parity = UART_PARITY_NONE;
	huart1.Init.Mode = UART_MODE_TX_RX;
	huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
	huart1.Init.OverSampling = UART_OVERSAMPLING_16;
	huart1.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
	huart1.Init.ClockPrescaler = UART_PRESCALER_DIV1;
	huart1.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetTxFifoThreshold(&huart1, UART_TXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_SetRxFifoThreshold(&huart1, UART_RXFIFO_THRESHOLD_1_8) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_UARTEx_DisableFifoMode(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
/* USER CODE BEGIN MX_GPIO_Init_1 */
/* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOA_CLK_ENABLE();

/* USER CODE BEGIN MX_GPIO_Init_2 */
/* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
