package cipher;

/**
 * Шифр Вернама (режим однократного гамування): побайтове додавання даних
 * з гамою за модулем 2 (XOR). Клас не зберігає стану, тому придатний для
 * будь-якого ключа і будь-якої довжини повідомлення.
 *
 * <p>Формули з методичних вказівок: C(i) = M(i) XOR Key(i) -- зашифрування,
 * M(i) = C(i) XOR Key(i) -- розшифрування. Оскільки подвійне додавання
 * однієї й тієї самої величини за модулем 2 відновлює початкове значення
 * (X XOR Y XOR Y = X), обидві операції виконує один і той самий код.</p>
 */
public final class VernamCipher {

    public byte[] encrypt(byte[] plainBytes, GammaSource key) throws CipherException {
        return applyGamma(plainBytes, key);
    }

    public byte[] decrypt(byte[] cipherBytes, GammaSource key) throws CipherException {
        return applyGamma(cipherBytes, key);
    }

    /**
     * Знаходить гаму (ключ) за відомими відкритим текстом і шифротекстом:
     * Key(i) = M(i) XOR C(i). Використовується для розв'язання оберненої
     * задачі -- перевірки чи відновлення ключа, коли відомий і відкритий
     * текст, і шифротекст.
     */
    public byte[] recoverGamma(byte[] plainBytes, byte[] cipherBytes) throws CipherException {
        return xor(plainBytes, cipherBytes);
    }

    private byte[] applyGamma(byte[] data, GammaSource key) throws CipherException {
        return xor(data, key.gammaFor(data.length));
    }

    private byte[] xor(byte[] left, byte[] right) throws CipherException {
        if (left.length != right.length) {
            throw new CipherException("Довжина гами (" + right.length
                    + " байт) повинна збігатися з довжиною тексту (" + left.length + " байт).");
        }
        byte[] result = new byte[left.length];
        for (int i = 0; i < left.length; i++) {
            result[i] = (byte) (left[i] ^ right[i]);
        }
        return result;
    }
}
