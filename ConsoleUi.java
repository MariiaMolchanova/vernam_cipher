package cipher;

import java.io.File;
import java.io.PrintStream;
import java.util.Scanner;

/**
 * Консольний інтерфейс програми. Перед кожним показом меню виводяться
 * поточний ключ і поточна фраза, тому весь стан сеансу видно в одному
 * протоколі роботи.
 *
 * <p>Ключ можна отримати одним із трьох способів: автоматично через ЛКГ
 * (криптографічно-безпечний seed, без повторів у сесії), вручну через ЛКГ
 * (відомий seed -- для відтворюваних демонстрацій) або через справжній
 * випадковий генератор SecureRandom, прив'язаний до довжини поточної
 * фрази. Усі три способи повертають {@link GammaSource}, з яким однаково
 * працює VernamCipher. Шифрування і розшифрування розділені за поданням
 * шифротексту (двійкове / шістнадцяткове) окремими пунктами меню.</p>
 */
public final class ConsoleUi {

    private static final String MENU_EXIT = "0";
    private static final String MENU_LCG_AUTO_KEY = "1";
    private static final String MENU_LCG_MANUAL_KEY = "2";
    private static final String MENU_SECURE_RANDOM_KEY = "3";
    private static final String MENU_BUILD_TEAM_PHRASE = "4";
    private static final String MENU_BUILD_CUSTOM_PHRASE = "5";
    private static final String MENU_SHOW_BINARY = "6";
    private static final String MENU_SHOW_HEX = "7";
    private static final String MENU_ENCRYPT_BINARY = "8";
    private static final String MENU_ENCRYPT_HEX = "9";
    private static final String MENU_DECRYPT_BINARY = "10";
    private static final String MENU_DECRYPT_HEX = "11";
    private static final String MENU_ENCRYPT_FILE = "12";
    private static final String MENU_DECRYPT_FILE = "13";

    private static final String SEPARATOR =
            "-----------------------------------------------------------";

    private static final String PROMPT_CHOICE = "Ваш вибір: ";
    private static final String PROMPT_SEED = "Введіть seed генератора (ціле невід'ємне число): ";
    private static final String PROMPT_CUSTOM_PHRASE = "Введіть довільну фразу: ";
    private static final String PROMPT_TEXT_OR_ENTER =
            "Введіть текст (Enter -- використати поточну фразу): ";
    private static final String PROMPT_CIPHER_BINARY = "Введіть шифротекст у двійковому вигляді: ";
    private static final String PROMPT_CIPHER_HEX = "Введіть шифротекст у шістнадцятковому вигляді: ";
    private static final String PROMPT_SOURCE_FILE = "Файл-джерело: ";
    private static final String PROMPT_TARGET_FILE = "Файл-результат: ";

    private final VernamCipher cipher;
    private final TextFileService fileService;
    private final SecureSeedGenerator seedGenerator;
    private final Scanner input;
    private final PrintStream output;
    private final String[] teamSurnames;

    private GammaSource key;
    private String currentPhrase;

    public ConsoleUi(VernamCipher cipher,
                      TextFileService fileService,
                      SecureSeedGenerator seedGenerator,
                      Scanner input,
                      PrintStream output,
                      String[] teamSurnames) throws CipherException {
        this.cipher = cipher;
        this.fileService = fileService;
        this.seedGenerator = seedGenerator;
        this.input = input;
        this.output = output;
        this.teamSurnames = teamSurnames;
        this.currentPhrase = "";
        // Перший ключ сесії одразу отримується автоматично через ЛКГ з
        // безпечно згенерованим seed -- без участі користувача.
        this.key = new LcgGammaKey(seedGenerator.nextSeed());
    }

    /** Основний цикл роботи програми. */
    public void run() {
        output.println(SEPARATOR);
        output.println("  Однократне гамування (шифр Вернама)");
        output.println(SEPARATOR);

        while (true) {
            printState();
            printMenu();
            String choice = readLine(PROMPT_CHOICE);
            if (choice == null || choice.equals(MENU_EXIT)) {
                output.println("Роботу завершено.");
                return;
            }
            try {
                handleChoice(choice);
            } catch (CipherException exception) {
                output.println("ПОМИЛКА: " + exception.getMessage());
            }
        }
    }

    private void handleChoice(String choice) throws CipherException {
        switch (choice) {
            case MENU_LCG_AUTO_KEY:
                generateLcgKeyAutomatically();
                break;
            case MENU_LCG_MANUAL_KEY:
                setLcgKeyManually();
                break;
            case MENU_SECURE_RANDOM_KEY:
                generateSecureRandomKey();
                break;
            case MENU_BUILD_TEAM_PHRASE:
                buildPhraseFromSurnames();
                break;
            case MENU_BUILD_CUSTOM_PHRASE:
                buildCustomPhrase();
                break;
            case MENU_SHOW_BINARY:
                showPhraseAsBinary();
                break;
            case MENU_SHOW_HEX:
                showPhraseAsHex();
                break;
            case MENU_ENCRYPT_BINARY:
                encryptText(true);
                break;
            case MENU_ENCRYPT_HEX:
                encryptText(false);
                break;
            case MENU_DECRYPT_BINARY:
                decryptText(true);
                break;
            case MENU_DECRYPT_HEX:
                decryptText(false);
                break;
            case MENU_ENCRYPT_FILE:
                encryptFile();
                break;
            case MENU_DECRYPT_FILE:
                decryptFile();
                break;
            default:
                output.println("ПОМИЛКА: немає пункту меню «" + choice + "».");
        }
    }

    private void printState() {
        output.println();
        output.println("Поточний ключ: " + key.describe());
        output.println("Поточна фраза: "
                + (currentPhrase.isEmpty() ? "(не сформована)" : "\"" + currentPhrase + "\""));
    }

    private void printMenu() {
        output.println();
        output.println("  " + MENU_LCG_AUTO_KEY + "  - ЛКГ: згенерувати ключ автоматично (seed без повторів)");
        output.println("  " + MENU_LCG_MANUAL_KEY + "  - ЛКГ: задати ключ вручну (seed)");
        output.println("  " + MENU_SECURE_RANDOM_KEY + "  - SecureRandom: згенерувати справжній випадковий ключ");
        output.println("  " + MENU_BUILD_TEAM_PHRASE + "  - сформувати фразу з прізвищ бригади");
        output.println("  " + MENU_BUILD_CUSTOM_PHRASE + "  - сформувати довільну (іншу) фразу");
        output.println("  " + MENU_SHOW_BINARY + "  - показати поточну фразу у двійковому вигляді");
        output.println("  " + MENU_SHOW_HEX + "  - показати поточну фразу у шістнадцятковому вигляді");
        output.println("  " + MENU_ENCRYPT_BINARY + "  - зашифрувати текст (шифротекст -- двійково)");
        output.println("  " + MENU_ENCRYPT_HEX + "  - зашифрувати текст (шифротекст -- шістнадцятково)");
        output.println("  " + MENU_DECRYPT_BINARY + " - розшифрувати текст із двійкового подання");
        output.println("  " + MENU_DECRYPT_HEX + " - розшифрувати текст із шістнадцяткового подання");
        output.println("  " + MENU_ENCRYPT_FILE + " - зашифрувати вміст файлу");
        output.println("  " + MENU_DECRYPT_FILE + " - розшифрувати вміст файлу");
        output.println("  " + MENU_EXIT + "  - завершити роботу");
    }

    /**
     * ЛКГ-режим, автоматичний: seed видає SecureSeedGenerator, тому
     * гарантовано не повториться в межах сесії, а сама гама лишається
     * детермінованою функцією цього seed (можна відтворити повторним
     * викликом gammaFor).
     */
    private void generateLcgKeyAutomatically() throws CipherException {
        long seed = seedGenerator.nextSeed();
        key = new LcgGammaKey(seed);
        output.println("-> Згенеровано ключ ЛКГ: seed = " + seed
                + " (усього видано ключів у цій сесії: " + seedGenerator.issuedCount() + ").");
    }

    /** ЛКГ-режим, ручний: для відтворюваних демонстрацій із наперед відомим seed. */
    private void setLcgKeyManually() throws CipherException {
        long seed = readSeed();
        key = new LcgGammaKey(seed);
        output.println("Ключ ЛКГ прийнято.");
    }

    /**
     * SecureRandom-режим: генерує справжню випадкову послідовність байтів
     * рівно під довжину поточної фрази -- як класичний одноразовий
     * блокнот. На відміну від ЛКГ, цей ключ не можна відтворити повторно:
     * усі його байти показуються одразу, щоб їх можна було зберегти чи
     * передати захищеним каналом (як і вимагає лекція).
     */
    private void generateSecureRandomKey() throws CipherException {
        requirePhrase();
        int length = BinaryUtils.textToBytes(currentPhrase).length;
        SecureGammaKey secureKey = new SecureGammaKey(length);
        key = secureKey;
        output.println("-> Згенеровано ключ SecureRandom рівно під " + length + " байт поточної фрази.");
        output.println("   Цей ключ не можна відтворити повторно -- ось його повний вміст "
                + "(за потреби збережіть окремо):");
        output.println("   Ключ (двійково): " + BinaryUtils.bytesToBinaryString(secureKey.gammaFor(length)));
        output.println("   Ключ (hex):      " + BinaryUtils.bytesToHexString(secureKey.gammaFor(length)));
    }

    private long readSeed() throws CipherException {
        String value = readLine(PROMPT_SEED).trim();
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException exception) {
            throw new CipherException("Seed має бути цілим числом, а введено «" + value + "».",
                    exception);
        }
    }

    /** Виконує пункт А завдання: формує фразу з прізвищ бригади. */
    private void buildPhraseFromSurnames() {
        StringBuilder phrase = new StringBuilder();
        for (int i = 0; i < teamSurnames.length; i++) {
            phrase.append(teamSurnames[i]);
            if (i != teamSurnames.length - 1) {
                phrase.append(' ');
            }
        }
        currentPhrase = phrase.toString();
        output.println("-> Сформована фраза: \"" + currentPhrase + "\"");
    }

    /** Дозволяє замінити поточну фразу на будь-яку іншу, введену користувачем. */
    private void buildCustomPhrase() throws CipherException {
        String phrase = readLine(PROMPT_CUSTOM_PHRASE);
        if (phrase == null || phrase.isEmpty()) {
            throw new CipherException("Фраза не може бути порожньою.");
        }
        currentPhrase = phrase;
        output.println("-> Нова фраза: \"" + currentPhrase + "\"");
    }

    /** Виконує пункт Б завдання: показує поточну фразу у двійковій формі. */
    private void showPhraseAsBinary() throws CipherException {
        requirePhrase();
        byte[] phraseBytes = BinaryUtils.textToBytes(currentPhrase);
        output.println("-> Фраза (текст):    \"" + currentPhrase + "\"");
        output.println("-> Фраза (двійково): " + BinaryUtils.bytesToBinaryString(phraseBytes));
        output.println("-> Довжина у байтах: " + phraseBytes.length);
    }

    /** Додаткове (не обов'язкове завданням) подання фрази -- у шістнадцятковому вигляді. */
    private void showPhraseAsHex() throws CipherException {
        requirePhrase();
        byte[] phraseBytes = BinaryUtils.textToBytes(currentPhrase);
        output.println("-> Фраза (текст):           \"" + currentPhrase + "\"");
        output.println("-> Фраза (шістнадцятково):  " + BinaryUtils.bytesToHexString(phraseBytes));
        output.println("-> Довжина у байтах: " + phraseBytes.length);
    }

    private void requirePhrase() throws CipherException {
        if (currentPhrase.isEmpty()) {
            throw new CipherException("Спочатку сформуйте фразу (пункт " + MENU_BUILD_TEAM_PHRASE
                    + " або " + MENU_BUILD_CUSTOM_PHRASE + ").");
        }
    }

    /**
     * Виконує пункти В і Г завдання: накладає поточний ключ (яким би він
     * не був -- ЛКГ чи SecureRandom) на текст. Різниця між двома пунктами
     * меню -- лише в поданні, у якому показується отриманий шифротекст.
     */
    private void encryptText(boolean showBinary) throws CipherException {
        String typed = readLine(PROMPT_TEXT_OR_ENTER);
        String text = (typed == null || typed.isEmpty()) ? currentPhrase : typed;
        if (text.isEmpty()) {
            throw new CipherException("Немає тексту для шифрування: введіть текст або спочатку "
                    + "сформуйте фразу (пункт " + MENU_BUILD_TEAM_PHRASE + ").");
        }
        currentPhrase = text;

        byte[] plainBytes = BinaryUtils.textToBytes(text);
        byte[] gamma = key.gammaFor(plainBytes.length);
        byte[] cipherBytes = cipher.encrypt(plainBytes, key);

        output.println(SEPARATOR);
        output.println("Відкритий текст: \"" + text + "\"");
        if (showBinary) {
            output.println("Відкритий текст (двійково): " + BinaryUtils.bytesToBinaryString(plainBytes));
            output.println("Гама (двійково):             " + BinaryUtils.bytesToBinaryString(gamma));
            output.println("Шифротекст (двійково):       " + BinaryUtils.bytesToBinaryString(cipherBytes));
        } else {
            output.println("Відкритий текст (hex): " + BinaryUtils.bytesToHexString(plainBytes));
            output.println("Гама (hex):            " + BinaryUtils.bytesToHexString(gamma));
            output.println("Шифротекст (hex):      " + BinaryUtils.bytesToHexString(cipherBytes));
        }
        output.println("Оброблено байтів: " + plainBytes.length);
        output.println(SEPARATOR);
    }

    /**
     * Розшифровує текст, отриманий у явно вказаному поданні (двійковому
     * або шістнадцятковому). Якщо введений рядок насправді відповідає
     * іншому поданню, відповідний метод BinaryUtils повідомить про це
     * зрозумілою помилкою замість мовчазного неправильного результату.
     */
    private void decryptText(boolean fromBinary) throws CipherException {
        String raw = fromBinary ? readLine(PROMPT_CIPHER_BINARY) : readLine(PROMPT_CIPHER_HEX);
        if (raw == null || raw.trim().isEmpty()) {
            throw new CipherException("Введено порожній шифротекст.");
        }
        byte[] cipherBytes = fromBinary
                ? BinaryUtils.binaryStringToBytes(raw)
                : BinaryUtils.hexStringToBytes(raw);

        byte[] plainBytes = cipher.decrypt(cipherBytes, key);
        String plainText = BinaryUtils.bytesToText(plainBytes);

        output.println(SEPARATOR);
        output.println("Шифротекст (" + (fromBinary ? "двійково" : "hex") + "): " + raw.trim());
        output.println("Розшифрований текст: \"" + plainText + "\"");
        if (plainText.equals(currentPhrase)) {
            output.println("Перевірка пройдена: результат збігається з поточною фразою.");
        }
        output.println("Оброблено байтів: " + cipherBytes.length);
        output.println(SEPARATOR);
    }

    /** Зашифровує текстовий файл; шифротекст зберігається у вигляді hex-рядка. */
    private void encryptFile() throws CipherException {
        File source = new File(readLine(PROMPT_SOURCE_FILE).trim());
        File target = new File(readLine(PROMPT_TARGET_FILE).trim());

        String plainText = fileService.readText(source);
        if (plainText.isEmpty()) {
            throw new CipherException("Файл «" + source.getName() + "» порожній.");
        }
        byte[] plainBytes = BinaryUtils.textToBytes(plainText);
        byte[] cipherBytes = cipher.encrypt(plainBytes, key);
        String cipherHex = BinaryUtils.bytesToHexString(cipherBytes);
        fileService.writeText(target, cipherHex);

        output.println(SEPARATOR);
        output.println("Прочитано файл:  " + source.getAbsolutePath());
        output.println("Вміст файлу:     " + plainText);
        output.println("Шифротекст (hex): " + cipherHex);
        output.println("Записано файл:   " + target.getAbsolutePath());
        output.println("Оброблено байтів: " + plainBytes.length);
        output.println(SEPARATOR);
    }

    /** Розшифровує файл, що містить шифротекст у вигляді hex-рядка. */
    private void decryptFile() throws CipherException {
        File source = new File(readLine(PROMPT_SOURCE_FILE).trim());
        File target = new File(readLine(PROMPT_TARGET_FILE).trim());

        String cipherHex = fileService.readText(source);
        if (cipherHex.trim().isEmpty()) {
            throw new CipherException("Файл «" + source.getName() + "» порожній.");
        }
        byte[] cipherBytes = BinaryUtils.hexStringToBytes(cipherHex);
        byte[] plainBytes = cipher.decrypt(cipherBytes, key);
        String plainText = BinaryUtils.bytesToText(plainBytes);
        fileService.writeText(target, plainText);

        output.println(SEPARATOR);
        output.println("Прочитано файл:      " + source.getAbsolutePath());
        output.println("Шифротекст (hex):    " + cipherHex.trim());
        output.println("Розшифрований текст: " + plainText);
        output.println("Записано файл:       " + target.getAbsolutePath());
        output.println("Оброблено байтів: " + cipherBytes.length);
        output.println(SEPARATOR);
    }

    /** @return введений рядок або null, якщо введення завершилося */
    private String readLine(String prompt) {
        output.print(prompt);
        output.flush();
        if (!input.hasNextLine()) {
            output.println();
            return null;
        }
        return input.nextLine();
    }
}
