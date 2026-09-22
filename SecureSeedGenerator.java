package cipher;

import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

/**
 * Генерує криптографічно-безпечні значення seed для ключа гамування за
 * допомогою {@link SecureRandom} -- це Java-аналог генераторів без
 * патернів, рекомендованих на лекції (Python secrets, Rust rand). На
 * відміну від лінійного конгруентного генератора (ЛКГ), тут неможливо
 * передбачити наступне значення, знаючи попередні: SecureRandom
 * використовує непередбачуване системне джерело ентропії, а не
 * детерміновану формулу.
 *
 * <p>Клас додатково гарантує, що жоден seed не буде видано двічі за час
 * роботи однієї сесії програми, -- це прямо відповідає вимозі
 * одноразового використання ключа. Ручне введення того самого числа
 * користувачем цю гарантію забезпечити не може, тому саме для цього
 * потрібна автоматична генерація.</p>
 */
public final class SecureSeedGenerator {

    private static final long MIN_SEED = 0L;
    private static final long MAX_SEED = LcgGenerator.MODULUS - 1L;
    private static final long RANGE_SIZE = MAX_SEED - MIN_SEED + 1L;

    private final SecureRandom random = new SecureRandom();
    private final Set<Long> issuedSeeds = new HashSet<>();

    /**
     * Повертає новий, ще не виданий у цій сесії, криптографічно-безпечний
     * seed у межах [{@value #MIN_SEED}, {@value #MAX_SEED}].
     */
    public long nextSeed() {
        long seed;
        do {
            seed = Math.floorMod(random.nextLong(), RANGE_SIZE) + MIN_SEED;
        } while (!issuedSeeds.add(seed));
        return seed;
    }

    /** Кількість seed-значень, уже виданих у цій сесії (для довідки користувачу). */
    public int issuedCount() {
        return issuedSeeds.size();
    }
}
