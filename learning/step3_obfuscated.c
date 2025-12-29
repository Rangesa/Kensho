// ステップ3: 軽い難読化
#include <stdio.h>
#include <string.h>

// XOR暗号化された文字列
unsigned char encrypted_password[] = {
    0x5E, 0x7B, 0x48, 0x64, 0x62, 0x73, 0x64, 0x71, 0x45, 0x60, 0x72, 0x72, 0x76, 0x6E, 0x73, 0x63
};
int password_length = 16;
char xor_key = 0x42;

void decrypt_password(char* output) {
    for (int i = 0; i < password_length; i++) {
        output[i] = encrypted_password[i] ^ xor_key;
    }
    output[password_length] = '\0';
}

int verify_password(const char* input) {
    char decrypted[64];
    decrypt_password(decrypted);
    return strcmp(input, decrypted) == 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Enter password: ");
        return 1;
    }

    if (verify_password(argv[1])) {
        printf("Welcome! You found the secret.\n");
    } else {
        printf("Wrong password.\n");
    }

    return 0;
}
