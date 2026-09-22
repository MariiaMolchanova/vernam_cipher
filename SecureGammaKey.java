package cipher;

import java.security.SecureRandom;

/**
 * Ключ шифру на основі криптографічно-безпечного генератора
 * {@link SecureRandom} -- Java-аналога рекомендованих на лекції генераторів
 * без патернів (Python secrets, Rust rand).
 *
 * <p>На відміну від {@link LcgGammaKey}, тут немає компактного "зерна", з
 * якого можна було б заново обчислити ту саму гаму: усі байти справжньої
 * випадкової послідовності генеруються один раз одразу при створенні
 * ключа і зберігаються в пам'яті як є -- саме так і влаштований класичний
 * одноразовий блокнот (one-time pad), де ключем є вже готова випадкова
 * послідовність, а не формула для її обчислення. Тому такий ключ одразу
 * готується під конкретну довжину повідомлення: {@link #gammaFor(int)}
 * віддає збережені байти лише тоді, коли запитана довжина точно збігається
 * з тією, під яку ключ був згенерований, -- для іншої довжини потрібен
 * новий ключ.</p>
 */
public final class SecureGammaKey implements GammaSource {

    private final byte[] gamma;

    /**
     * Генерує {@code length} байтів справжньої випадкової гами.
     *
     * @param length довжина ключа (і, відповідно, повідомлення) в байтах
     * @throws CipherException якщо довжина від'ємна
     */
    public SecureGammaKey(int length) throws CipherException {
        if (length < 0) {
            throw new CipherException("Довжина ключа не може бути від'ємною.");
        }
        this.gamma = new byte[length];
        new SecureRandom().nextBytes(this.gamma);
    }

    @Override
    public byte[] gammaFor(int length) throws CipherException {
        if (length != gamma.length) {
            throw new CipherException("Цей ключ згенеровано SecureRandom рівно під "
                    + gamma.length + " байт повідомлення, а запитано " + length
                    + ". Справжній випадковий ключ не можна розтягнути чи скоротити -- "
                    + "згенеруйте новий ключ під нову довжину тексту.");
        }
        return gamma.clone();
    }

    @Override
    public String describe() {
        return "SecureRandom, " + gamma.length + " байт випадкового ключа";
    }

    /** Довжина цього ключа в байтах -- для перевірки перед використанням. */
    public int length() {
        return gamma.length;
    }
}
