package cipher;

import java.io.PrintStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

/**
 * Точка входу програми. Тут задані початкові значення параметрів (прізвища
 * бригади та seed за замовчуванням); ключ користувач змінює з меню під час
 * роботи, без перекомпіляції.
 */
public final class Main {

    private static final String[] TEAM_SURNAMES = {"Tatarnikova", "Molchanova", "Chorna"};
    private static final Charset FILE_CHARSET = StandardCharsets.UTF_8;

    private Main() {
    }

    public static void main(String[] args) {
        PrintStream output = new PrintStream(System.out, true, FILE_CHARSET);
        try {
            ConsoleUi ui = new ConsoleUi(
                    new VernamCipher(),
                    new TextFileService(FILE_CHARSET),
                    new SecureSeedGenerator(),
                    new Scanner(System.in, FILE_CHARSET),
                    output,
                    TEAM_SURNAMES);
            ui.run();
        } catch (CipherException exception) {
            output.println("ПОМИЛКА: " + exception.getMessage());
        }
    }
}
