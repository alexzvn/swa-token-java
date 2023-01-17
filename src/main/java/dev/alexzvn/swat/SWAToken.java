package dev.alexzvn.swat;

import dev.alexzvn.swat.signature.ShasumSignatureProvider;
import dev.alexzvn.swat.signature.SignatureProvider;
import dev.alexzvn.swat.token.SignedToken;
import dev.alexzvn.swat.token.Token;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class SWAToken {
    protected Map<String, SignatureProvider> provider = new HashMap<String, SignatureProvider>();

    /**
     * Selected signature provider
     */
    protected String algo;


    final protected String NAME = "swat";

    /**
     * Create new SWAToken instance with default signature provider (HS256, HS384, HS512)
     * @param secret secret key used to sign token
     */
    public SWAToken(String secret) {
        try {
            use("HS256", new ShasumSignatureProvider(secret, "HmacSHA256"));
            register("HS512", new ShasumSignatureProvider(secret, "HmacSHA512"));
            register("HS384", new ShasumSignatureProvider(secret, "HmacSHA384"));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create new SWAToken instance with custom signature provider
     * @param algo signature provider name
     * @param provider signature provider
     */
    public SWAToken(String algo, SignatureProvider provider) {
        use(algo, provider);
    }

    /**
     * create a new token with expired date
     * @param ttl in seconds
     */
    public SignedToken create(String issuer, String subject, int ttl) {
        Long current = timestamp();

        return quickSign(new Token(NAME, algo, issuer, subject, current, current + ttl));
    }

    public SignedToken create(String issuer, String subject) {
        return quickSign(new Token(NAME, algo, issuer, subject, timestamp(), null));
    }

    public boolean verify(String token) throws Token.InvalidTokenFormatException {
        if (! SignedToken.validate(token)) {
            return false;
        }

        Token _token = Token.parse(token);

        if (! (_token instanceof SignedToken signedToken)) {
            return false;
        }

        if (! quickVerify(signedToken)) {
            return false;
        }

        if (signedToken.expires_at != null) {
            return signedToken.expires_at > timestamp();
        }

        return true;
    }

    public void use(String algo) {
        if (!this.provider.containsKey(algo)) {
            throw new RuntimeException("Signature provider " + algo + " not found");
        }

        this.algo = algo;
    }

    public void register(String algo, SignatureProvider provider) {
        this.provider.put(algo, provider);
    }

    public void use(String algo, SignatureProvider provider) {
        register(algo, provider);
        use(algo);
    }

    public SignatureProvider getCurrentProvider() {
        return this.provider.get(this.algo);
    }

    public SignatureProvider getProvider(String algo) {
        return this.provider.get(algo);
    }

    protected Long timestamp() {
        return System.currentTimeMillis() / 1000L;
    }

    protected SignedToken quickSign(Token token) {
        return new SignedToken(token, getCurrentProvider().sign(token.getToken()));
    }

    protected boolean quickVerify(SignedToken token) {
        SignatureProvider signer = getProvider(token.algo);

        if (signer == null) {
            return false;
        }

        return signer.verify(token.getToken(), token.signature);
    }
}
