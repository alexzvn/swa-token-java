package dev.alexzvn.swat.token;

public class Token {
    /**
     * Name of the token should always return "swat"
     */
    final public String name;

    /**
     * Algorithm used to create the signature
     */
    final public  String algo;

    final public String issuer;

    final public String subject;

    final public Long issued_at;

    final public Long expires_at;

    public Token(String name, String algo, String issuer, String subject, Long issued_at, Long expires_at) {
        this.name = check(name);
        this.algo = check(algo);
        this.issuer = check(issuer);
        this.subject = check(subject);
        this.issued_at = issued_at;
        this.expires_at = expires_at;
    }

    public String getToken() {
        final String issued_at = this.issued_at == null ? "" : this.issued_at.toString();
        final String expires_at = this.expires_at == null ? "" : this.expires_at.toString();

        final String head = String.format("%s:%s", name, algo);
        final String payload = String.format("%s:%s:%s:%s", issuer, subject, issued_at, expires_at);

        return String.format("%s.%s", head, payload);
    }

    public static boolean validate(String token) {
        return token.matches("swat:[a-zA-Z0-9]+\\.?[a-zA-Z0-9]+:?[a-zA-Z0-9]+:?[0-9]+:?[0-9]+:?(\\.[^.]+)");
    }

    protected String check(String param) {
        if (param == null) {
            return "";
        }

        if (param.contains(".") || param.contains(":")) {
            throw new IllegalArgumentException("Token param can not contains '.' or ':'");
        }

        return param;
    }

    public static Token parse(String token) throws InvalidTokenFormatException {
        if (! validate(token)) {
            throw new InvalidTokenFormatException("Token is not following the format");
        }

        String[] parts = token.split("\\.");
        String[] head = parts[0].split(":");
        String[] payload = parts[1].split(":");
        String signature = parts.length == 3 ? parts[2] : null;

        Long issued_at = access(payload, 2) != null ? Long.parseLong(payload[2]) : null;
        Long expires_at = access(payload, 3) != null ? Long.parseLong(payload[3]) : null;

        final Token _token = new Token(
            access(head, 0),
            access(head, 1),
            access(payload, 0),
            access(payload, 1),
            issued_at,
            expires_at
        );

        return signature != null ? new SignedToken(_token, signature) : _token;
    }

    protected static <T> T access(T[] parts, int index) {
        if (parts.length <= index) {
            return null;
        }

        return parts[index];
    }

    @Override
    public String toString() {
        return getToken();
    }

    public static class InvalidTokenFormatException extends Exception {
        public InvalidTokenFormatException(String message) {
            super(message);
        }
    }
}
