package cipher;

/**
 * Лінійний конгруентний генератор (ЛКГ) псевдовипадкових чисел:
 *
 * <pre>X(n+1) = (a * X(n) + c) mod m</pre>
 *
 * Клас реалізує лише математику генератора і не перевіряє коректність
 * бізнес-обмежень (діапазон seed, невід'ємність довжини) -- це
 * відповідальність {@link LcgGammaKey}, яка викликає цей клас уже після
 * власної перевірки параметрів.
 */
public final class LcgGenerator {

    /** Множник "a" (параметри запозичені з генератора Numerical Recipes). */
    private static final long MULTIPLIER = 1_664_525L;

    /** Приріст "c". */
    private static final long INCREMENT = 1_013_904_223L;

    /** Модуль "m" генератора, дорівнює 2^32. Публічний -- визначає межі seed. */
    public static final long MODULUS = 4_294_967_296L;

    /** Модуль, за яким чергове число послідовності зводиться до одного байта. */
    private static final int BYTE_MODULUS = 256;

    private LcgGenerator() {
    }

    /**
     * Генерує послідовність байтів заданої довжини, починаючи від стану
     * {@code seed}. Виклик з тим самим {@code seed} завжди повертає
     * однакову послідовність -- це і є "ключем" шифру.
     *
     * @param seed   початковий стан генератора X(0), 0 &le; seed &lt; {@link #MODULUS}
     * @param length потрібна кількість байтів, невід'ємна
     */
    public static byte[] generate(long seed, int length) {
        byte[] gamma = new byte[length];
        long state = seed;
        for (int i = 0; i < length; i++) {
            state = (MULTIPLIER * state + INCREMENT) % MODULUS;
            gamma[i] = (byte) (state % BYTE_MODULUS);
        }
        return gamma;
    }
}
