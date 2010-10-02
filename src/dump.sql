create table yubikeys(
	publicname varchar(16) unique not null,
	created varchar(24) not null,
	internalname varchar(12) not null,
	aeskey varchar(32) not null,
	active boolean default true,
	counter integer not null default 1,
	time integer not null  default 1
);
