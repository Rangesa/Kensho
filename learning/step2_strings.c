// ステップ2: 文字列を扱うプログラム
#include <stdio.h>
#include <string.h>

void check_password(const char* input) {
    const char* secret = "MySecretPassword123";

    if (strcmp(input, secret) == 0) {
        printf("Access Granted!\n");
    } else {
        printf("Access Denied!\n");
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    check_password(argv[1]);
    return 0;
}
