package cipher;

import java.nio.charset.StandardCharsets;

/**
 * Перетворення даних між поданнями, які використовуються протоколом
 * однократного гамування: текст (UTF-8), масив байтів, рядок з '0'/'1'
 * (двійкове подання) та рядок шістнадцяткових пар (зручний компактний
 * запис довільних байтів, зокрема шифротексту). Клас складається лише зі
 * статичних методів, що не мають стану, і не створюється.
 */
public final class BinaryUtils {

    private static final int BITS_IN_BYTE = 8;
    private static final int BINARY_RADIX = 2;
    private static final int HEX_RADIX = 16;
    private static final int HEX_CHARS_IN_BYTE = 2;
    private static final char BINARY_PAD_CHAR = '0';
    private static final String HEX_FORMAT = "%02X";

    /** Рядок містить лише символи '0' і '1' -- дійсне як двійкове, так і шістнадцяткове подання. */
    private static final String BINARY_PATTERN = "[01]+";

    /** Рядок містить лише коректні шістнадцяткові цифри. */
    private static final String HEX_PATTERN = "[0-9A-Fa-f]+";

    /**
     * Мінімальна довжина (у значущих символах), з якої рядок, що складається
     * лише з '0' і '1', вважається "підозріло схожим" на подання в іншій
     * системі числення, а не на випадковий короткий збіг. Для довших
     * шифротекстів імовірність того, що всі шістнадцяткові цифри справжнього
     * шифротексту випадково виявились лише '0' або '1', практично нульова.
     */
    private static final int AMBIGUITY_THRESHOLD = 8;

    private BinaryUtils() {
    }

    /** Кодує текст у байти UTF-8 -- саме в цьому поданні текст шифрується. */
    public static byte[] textToBytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    /** Відновлює текст із байтів UTF-8. */
    public static String bytesToText(byte[] data) {
        return new String(data, StandardCharsets.UTF_8);
    }

    /**
     * Подає масив байтів у вигляді рядка з двійкових розрядів: рівно
     * {@value #BITS_IN_BYTE} біт на кожен байт, байти розділені пробілом.
     */
    public static String bytesToBinaryString(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            result.append(padLeft(Integer.toBinaryString(data[i] & 0xFF)));
            if (i != data.length - 1) {
                result.append(' ');
            }
        }
        return result.toString();
    }

    /**
     * Виконує обернене перетворення: з рядка двійкових розрядів (пробіли й
     * переходи на новий рядок ігноруються) відновлює масив байтів.
     *
     * @throws CipherException якщо довжина значущих символів не кратна 8
     *                         або серед них є символ, відмінний від '0'/'1'
     */
    public static byte[] binaryStringToBytes(String binaryText) throws CipherException {
        String cleaned = binaryText.replaceAll("\\s+", "");
        if (cleaned.isEmpty()) {
            return new byte[0];
        }
        if (!cleaned.matches(BINARY_PATTERN)) {
            if (cleaned.matches(HEX_PATTERN)) {
                throw new CipherException("Введений рядок містить символи, яких немає в "
                        + "двійковому поданні (допустимі лише '0' і '1'). Схоже, ви вставили "
                        + "шифротекст у шістнадцятковому вигляді -- скористайтеся пунктом меню "
                        + "для розшифрування із шістнадцяткового подання.");
            }
            throw new CipherException("Двійковий запис може містити лише символи '0' і '1'.");
        }
        if (cleaned.length() % BITS_IN_BYTE != 0) {
            throw new CipherException("Довжина двійкового запису (" + cleaned.length()
                    + " символів) має бути кратною " + BITS_IN_BYTE + ".");
        }
        byte[] result = new byte[cleaned.length() / BITS_IN_BYTE];
        for (int i = 0; i < result.length; i++) {
            String byteBits = cleaned.substring(i * BITS_IN_BYTE, (i + 1) * BITS_IN_BYTE);
            result[i] = (byte) Integer.parseInt(byteBits, BINARY_RADIX);
        }
        return result;
    }

    /** Подає масив байтів компактним рядком шістнадцяткових пар через пробіл. */
    public static String bytesToHexString(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            result.append(String.format(HEX_FORMAT, data[i] & 0xFF));
            if (i != data.length - 1) {
                result.append(' ');
            }
        }
        return result.toString();
    }

    /**
     * Відновлює масив байтів із рядка шістнадцяткових пар (пробіли й
     * переходи на новий рядок ігноруються).
     *
     * @throws CipherException якщо кількість шістнадцяткових цифр непарна
     *                         або серед них є символ поза [0-9A-Fa-f]
     */
    public static byte[] hexStringToBytes(String hexText) throws CipherException {
        String cleaned = hexText.replaceAll("\\s+", "");
        if (cleaned.isEmpty()) {
            return new byte[0];
        }
        if (cleaned.length() >= AMBIGUITY_THRESHOLD && cleaned.matches(BINARY_PATTERN)) {
            // Рядок технічно є коректним hex (0 і 1 -- валідні шістнадцяткові цифри),
            // але для довгого рядка це майже напевно означає, що сюди вставили
            // саме двійкове подання -- інакше довелося б випадково отримати
            // шифротекст, усі байти якого лежать у межах 0x00-0x11.
            throw new CipherException("Введений рядок складається лише із символів '0' і '1', "
                    + "що більше схоже на двійкове подання шифротексту, ніж на шістнадцяткове. "
                    + "Якщо це так, скористайтеся пунктом меню для розшифрування "
                    + "з двійкового подання.");
        }
        if (!cleaned.matches(HEX_PATTERN)) {
            throw new CipherException("Шістнадцятковий запис може містити лише цифри 0-9 "
                    + "та літери A-F.");
        }
        if (cleaned.length() % HEX_CHARS_IN_BYTE != 0) {
            throw new CipherException("Шістнадцятковий запис має містити парну "
                    + "кількість цифр, а містить " + cleaned.length() + ".");
        }
        byte[] result = new byte[cleaned.length() / HEX_CHARS_IN_BYTE];
        for (int i = 0; i < result.length; i++) {
            String bytePair = cleaned.substring(i * HEX_CHARS_IN_BYTE, (i + 1) * HEX_CHARS_IN_BYTE);
            result[i] = (byte) Integer.parseInt(bytePair, HEX_RADIX);
        }
        return result;
    }

    private static String padLeft(String bits) {
        StringBuilder padded = new StringBuilder();
        for (int i = bits.length(); i < BITS_IN_BYTE; i++) {
            padded.append(BINARY_PAD_CHAR);
        }
        padded.append(bits);
        return padded.toString();
    }
}
