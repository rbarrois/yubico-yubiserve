BEGIN TRANSACTION;
create table yubikeys(
 nickname varchar(16) unique not null,
 publicname varchar(16) unique not null,
 created varchar(24) not null,
 internalname varchar(12) not null,
 aeskey varchar(32) not null,
 active boolean default true,
 counter integer not null default 1,
 time integer not null default 1
);
create table oathtokens(
 nickname varchar(16) unique not null,
 publicname varchar(12) unique not null,
 created varchar(24) not null,
 secret varchar(40) not null,
 active boolean default true,
 counter integer not null default 1
);
create table apikeys(
 nickname varchar(16),
 secret varchar(28),
 id integer primary key
);
COMMIT;
