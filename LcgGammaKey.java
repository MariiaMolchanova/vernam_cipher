package cipher;

/**
 * Ключ шифру на основі лінійного конгруентного генератора (ЛКГ).
 *
 * Роль компактного ключа тут відіграє початковий стан {@code seed}
 * генератора: сама гама детерміновано обчислюється з нього під будь-яку
 * потрібну довжину методом {@link #gammaFor(int)} -- так само, як
 * шифрувальний алфавіт обчислюється з ключового слова в шифрі Цезаря.
 * Це дозволяє одним і тим самим компактним ключем зашифрувати, а потім
 * розшифрувати повідомлення будь-якої довжини, лише повторно викликавши
 * генератор. Водночас послідовність ЛКГ детермінована й теоретично
 * відновлювана за відомими параметрами й кількома вихідними байтами, тому
 * для реального захисту даних варто використовувати {@link SecureGammaKey}.
 */
public final class LcgGammaKey implements GammaSource {

    private static final long MIN_SEED = 0L;
    private static final long MAX_SEED = LcgGenerator.MODULUS - 1L;

    private final long seed;

    public LcgGammaKey(long seed) throws CipherException {
        this.seed = validateSeed(seed);
    }

    private static long validateSeed(long seed) throws CipherException {
        if (seed < MIN_SEED || seed > MAX_SEED) {
            throw new CipherException("Початковий стан генератора (seed) має бути "
                    + "в межах від " + MIN_SEED + " до " + MAX_SEED + ", а введено " + seed + ".");
        }
        return seed;
    }

    @Override
    public byte[] gammaFor(int length) throws CipherException {
        if (length < 0) {
            throw new CipherException("Довжина гами не може бути від'ємною.");
        }
        return LcgGenerator.generate(seed, length);
    }

    @Override
    public String describe() {
        return "ЛКГ, seed = " + seed;
    }

    public long getSeed() {
        return seed;
    }
}
