package dev.alexzvn.swat.token;

public class SignedToken extends Token {
    final public String signature;

    public SignedToken(String name, String algo, String issuer, String subject, Long issued_at, Long expires_at, String signature) {
        super(name, algo, issuer, subject, issued_at, expires_at);
        this.signature = check(signature);
    }

    public SignedToken(Token token, String signature) {
        super(token.name, token.algo, token.issuer, token.subject, token.issued_at, token.expires_at);
        this.signature = check(signature);
    }

    public String getToken() {
        return super.getToken();
    }

    public String getSignedToken() {
        return String.format("%s.%s", super.getToken(), signature);
    }

    @Override
    public String toString() {
        return getSignedToken();
    }
}
