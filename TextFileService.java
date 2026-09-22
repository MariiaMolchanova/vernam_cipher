package cipher;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;

/**
 * Читання та запис файлів. Відкритий текст читається й записується як
 * рядок у заданому кодуванні; шифротекст, який у загальному випадку не є
 * коректним текстом у жодному кодуванні, читається й записується як його
 * шістнадцяткове текстове подання -- це дозволяє зберігати й переглядати
 * результат шифрування звичайним текстовим редактором.
 *
 * <p>Усі помилки вводу-виводу перетворюються на {@link CipherException} із
 * зрозумілим повідомленням, тому інтерфейс програми не працює з класами
 * вводу-виводу напряму.</p>
 */
public final class TextFileService {

    private final Charset charset;

    public TextFileService(Charset charset) {
        this.charset = charset;
    }

    /** Читає файл як текст у заданому кодуванні. */
    public String readText(File file) throws CipherException {
        return new String(readAllBytes(file), charset);
    }

    /** Записує рядок у файл у заданому кодуванні. */
    public void writeText(File file, String content) throws CipherException {
        writeAllBytes(file, content.getBytes(charset));
    }

    private byte[] readAllBytes(File file) throws CipherException {
        if (!file.exists()) {
            throw new CipherException("Файл «" + file.getPath() + "» не знайдено.");
        }
        if (file.isDirectory()) {
            throw new CipherException("«" + file.getPath() + "» є каталогом, а не файлом.");
        }
        if (!file.canRead()) {
            throw new CipherException("Немає прав на читання файлу «" + file.getPath() + "».");
        }
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException exception) {
            throw new CipherException("Не вдалося прочитати файл «" + file.getPath()
                    + "»: " + exception.getMessage(), exception);
        }
    }

    private void writeAllBytes(File file, byte[] content) throws CipherException {
        if (file.exists() && !file.canWrite()) {
            throw new CipherException("Немає прав на запис у файл «" + file.getPath() + "».");
        }
        try {
            Files.write(file.toPath(), content);
        } catch (IOException exception) {
            throw new CipherException("Не вдалося записати файл «" + file.getPath()
                    + "»: " + exception.getMessage(), exception);
        }
    }

    public Charset getCharset() {
        return charset;
    }
}
