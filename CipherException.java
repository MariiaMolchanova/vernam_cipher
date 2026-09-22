package cipher;

/**
 * Передбачувана помилка роботи програми: некоректний ключ (seed), хибний
 * шістнадцятковий запис шифротексту, невдале читання або запис файлу.
 * Повідомлення виводиться користувачеві без додаткової обробки.
 */
public class CipherException extends Exception {

    public CipherException(String message) {
        super(message);
    }

    public CipherException(String message, Throwable cause) {
        super(message, cause);
    }
}
