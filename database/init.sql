-- خزنة واحدة (صف واحد). السيرفر لا يعرف كلمة السر الرئيسية ولا مفتاح التشفير.
CREATE TABLE IF NOT EXISTS vault (
    id         SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    salt       VARCHAR(64) NOT NULL,
    iterations INTEGER     NOT NULL CHECK (iterations >= 100000),
    auth_hash  TEXT        NOT NULL,
    created_at TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- كل صف = حساب واحد، مخزّن كنص مشفّر (AES-GCM) من المتصفح.
CREATE TABLE IF NOT EXISTS entries (
    id         SERIAL PRIMARY KEY,
    data       TEXT      NOT NULL CHECK (char_length(data) BETWEEN 1 AND 20000),
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);
