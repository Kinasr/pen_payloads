package main

type Database struct {
	name string
	versionFunction string
	concatenation string
}

var (
	ORACLE = Database{
		name: "Oracle",
		versionFunction: "version FROM v$instance",
		concatenation: "||",
	}
	MSSQL = Database{
		name: "MSSQL",
		versionFunction: "@@version",
		concatenation: "+",
	}
	MYSQL = Database{
		name: "MySQL",
		versionFunction: "@@version",
		concatenation: " ",
	}
	POSTGRESQL = Database{
		name: "PostgreSQL",
		versionFunction: "version()",
		concatenation: "||",
	}
)

var databases = []Database{
	ORACLE,
	MSSQL,
	MYSQL,
	POSTGRESQL,
}