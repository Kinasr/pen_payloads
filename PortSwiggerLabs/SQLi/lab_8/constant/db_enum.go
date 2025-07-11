package constant

type Database struct {
	Name string
	VersionFunction string
	Concatenation string
	Comment []string
}

var (
	ORACLE = Database{
		Name: "Oracle",
		VersionFunction: "version FROM v$instance",
		Concatenation: "||",
		Comment: []string{DOUBLE_DASH_COMMENT},
	}
	MSSQL = Database{
		Name: "MSSQL",
		VersionFunction: "@@version",
		Concatenation: "+",
		Comment: []string{DOUBLE_DASH_COMMENT},
	}
	MYSQL = Database{
		Name: "MySQL",
		VersionFunction: "@@version",
		Concatenation: " ",
		Comment: []string{DOUBLE_DASH_COMMENT_WITH_SPACE, HASH_COMMENT},
	}
	POSTGRESQL = Database{
		Name: "PostgreSQL",
		VersionFunction: "version()",
		Concatenation: "||",
		Comment: []string{DOUBLE_DASH_COMMENT},
	}
)

var Databases = []Database{
	ORACLE,
	MSSQL,
	MYSQL,
	POSTGRESQL,
}