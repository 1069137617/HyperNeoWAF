package analyzer

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

type NodeType int

const (
	NodeTypeUnknown NodeType = iota
	NodeTypeSelect
	NodeTypeFrom
	NodeTypeWhere
	NodeTypeUnion
	NodeTypeJoin
	NodeTypeGroupBy
	NodeTypeOrderBy
	NodeTypeHaving
	NodeTypeLimit
	NodeTypeInsert
	NodeTypeUpdate
	NodeTypeDelete
	NodeTypeDrop
	NodeTypeCreate
	NodeTypeAlter
	NodeTypeExecute
	NodeTypeSubquery
	NodeTypeCondition
	NodeTypeExpression
	NodeTypeColumn
	NodeTypeTable
	NodeTypeValue
)

func (n NodeType) String() string {
	switch n {
	case NodeTypeUnknown:
		return "UNKNOWN"
	case NodeTypeSelect:
		return "SELECT"
	case NodeTypeFrom:
		return "FROM"
	case NodeTypeWhere:
		return "WHERE"
	case NodeTypeUnion:
		return "UNION"
	case NodeTypeJoin:
		return "JOIN"
	case NodeTypeGroupBy:
		return "GROUP_BY"
	case NodeTypeOrderBy:
		return "ORDER_BY"
	case NodeTypeHaving:
		return "HAVING"
	case NodeTypeLimit:
		return "LIMIT"
	case NodeTypeInsert:
		return "INSERT"
	case NodeTypeUpdate:
		return "UPDATE"
	case NodeTypeDelete:
		return "DELETE"
	case NodeTypeDrop:
		return "DROP"
	case NodeTypeCreate:
		return "CREATE"
	case NodeTypeAlter:
		return "ALTER"
	case NodeTypeExecute:
		return "EXECUTE"
	case NodeTypeSubquery:
		return "SUBQUERY"
	case NodeTypeCondition:
		return "CONDITION"
	case NodeTypeExpression:
		return "EXPRESSION"
	case NodeTypeColumn:
		return "COLUMN"
	case NodeTypeTable:
		return "TABLE"
	case NodeTypeValue:
		return "VALUE"
	default:
		return "UNKNOWN"
	}
}

type SQLNode struct {
	NodeType     NodeType
	Value        string
	Children     []*SQLNode
	Parent       *SQLNode
	Position     int
	Length       int
	RawText      string
	Attributes   map[string]interface{}
	IsMalicious  bool
	ThreatLevel  ThreatLevel
	ThreatType   string
}

func NewSQLNode(nodeType NodeType, value string) *SQLNode {
	return &SQLNode{
		NodeType:   nodeType,
		Value:      value,
		Children:   make([]*SQLNode, 0),
		Attributes: make(map[string]interface{}),
	}
}

func (n *SQLNode) AddChild(child *SQLNode) {
	child.Parent = n
	n.Children = append(n.Children, child)
}

func (n *SQLNode) String() string {
	return fmt.Sprintf("SQLNode{Type:%s, Value:%s, Children:%d}", n.NodeType, n.Value, len(n.Children))
}

type SQLAST struct {
	Root       *SQLNode
	RawSQL     string
	Tokens     []*SQLToken
	Statements []*SQLNode
	Metadata   map[string]interface{}
}

func NewSQLAST(sql string) *SQLAST {
	return &SQLAST{
		RawSQL:     sql,
		Tokens:     make([]*SQLToken, 0),
		Statements: make([]*SQLNode, 0),
		Metadata:   make(map[string]interface{}),
	}
}

type TokenType int

const (
	TokenTypeUnknown TokenType = iota
	TokenTypeKeyword
	TokenTypeIdentifier
	TokenTypeString
	TokenTypeNumber
	TokenTypeOperator
	TokenTypePunctuation
	TokenTypeComment
	TokenTypeWhitespace
)

func (t TokenType) String() string {
	switch t {
	case TokenTypeUnknown:
		return "UNKNOWN"
	case TokenTypeKeyword:
		return "KEYWORD"
	case TokenTypeIdentifier:
		return "IDENTIFIER"
	case TokenTypeString:
		return "STRING"
	case TokenTypeNumber:
		return "NUMBER"
	case TokenTypeOperator:
		return "OPERATOR"
	case TokenTypePunctuation:
		return "PUNCTUATION"
	case TokenTypeComment:
		return "COMMENT"
	case TokenTypeWhitespace:
		return "WHITESPACE"
	default:
		return "UNKNOWN"
	}
}

type SQLToken struct {
	Type     TokenType
	Value    string
	Position int
	Length   int
}

type SQLLexer struct {
	input   string
	pos     int
	tokens  []*SQLToken
 Keywords []string
}

func NewSQLLexer(input string) *SQLLexer {
	return &SQLLexer{
		input:   input,
		pos:     0,
		tokens:  make([]*SQLToken, 0),
		Keywords: []string{
			"SELECT", "FROM", "WHERE", "UNION", "JOIN", "LEFT", "RIGHT", "INNER", "OUTER",
			"GROUP", "ORDER", "BY", "HAVING", "LIMIT", "OFFSET", "INSERT", "INTO", "VALUES",
			"UPDATE", "SET", "DELETE", "DROP", "CREATE", "ALTER", "INDEX", "TABLE", "DATABASE",
			"EXEC", "EXECUTE", "DECLARE", "CAST", "CONVERT", "VARCHAR", "INT", "CHAR",
			"AND", "OR", "NOT", "IN", "EXISTS", "BETWEEN", "LIKE", "IS", "NULL", "TRUE", "FALSE",
			"AS", "ON", "USING", "INTO", "OUTFILE", "DUMPFILE", "LOAD_FILE",
			"IF", "CASE", "WHEN", "THEN", "ELSE", "END", "BENCHMARK", "SLEEP", "WAITFOR",
			"XP_CMDSHELL", "XP_REGREAD", "XP_REGWRITE", "SP_EXECUTESQL", "OPENDATASOURCE",
			"OPENROWSET", "SUBSTRING", "ASCII", "CHAR", "CONCAT", "COUNT", "SUM", "AVG", "MIN", "MAX",
			"DISTINCT", "ALL", "ASC", "DESC", "UNION", "EXCEPT", "INTERSECT", "TOP", "FIRST",
			"GRANT", "REVOKE", "DENY", "TRUNCATE", "SHUTDOWN", "KILL", "DBCC",
		},
	}
}

func (l *SQLLexer) isAtEnd() bool {
	return l.pos >= len(l.input)
}

func (l *SQLLexer) current() byte {
	if l.isAtEnd() {
		return 0
	}
	return l.input[l.pos]
}

func (l *SQLLexer) peek() byte {
	if l.isAtEnd() {
		return 0
	}
	return l.input[l.pos]
}

func (l *SQLLexer) peekNext() byte {
	if l.pos+1 >= len(l.input) {
		return 0
	}
	return l.input[l.pos+1]
}

func (l *SQLLexer) advance() byte {
	if l.isAtEnd() {
		return 0
	}
	ch := l.input[l.pos]
	l.pos++
	return ch
}

func (l *SQLLexer) match(expected byte) bool {
	if l.isAtEnd() {
		return false
	}
	if l.input[l.pos] != expected {
		return false
	}
	l.pos++
	return true
}

func (l *SQLLexer) skipWhitespace() {
	for !l.isAtEnd() {
		ch := l.current()
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			l.advance()
		} else {
			break
		}
	}
}

func (l *SQLLexer) readString(quote byte) string {
	start := l.pos
	l.advance()
	for !l.isAtEnd() && l.current() != quote {
		if l.current() == '\\' && l.peek() == quote {
			l.advance()
		}
		l.advance()
	}
	if !l.isAtEnd() {
		l.advance()
	}
	return l.input[start:l.pos]
}

func (l *SQLLexer) readNumber() string {
	start := l.pos
	hasDecimal := false
	for !l.isAtEnd() {
		ch := l.current()
		if ch >= '0' && ch <= '9' {
			l.advance()
		} else if ch == '.' && !hasDecimal {
			hasDecimal = true
			l.advance()
		} else {
			break
		}
	}
	return l.input[start:l.pos]
}

func (l *SQLLexer) readIdentifier() string {
	start := l.pos
	for !l.isAtEnd() {
		ch := l.current()
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '$' || ch == '#' {
			l.advance()
		} else {
			break
		}
	}
	return l.input[start:l.pos]
}

func (l *SQLLexer) readComment() string {
	start := l.pos
	ch := l.current()
	if ch == '-' && l.peek() == '-' {
		for !l.isAtEnd() && l.current() != '\n' {
			l.advance()
		}
		return l.input[start:l.pos]
	}
	if ch == '/' && l.peek() == '*' {
		l.advance()
		l.advance()
		for !l.isAtEnd() {
			if l.current() == '*' && l.peek() == '/' {
				l.advance()
				l.advance()
				break
			}
			l.advance()
		}
		return l.input[start:l.pos]
	}
	if ch == '#' {
		for !l.isAtEnd() && l.current() != '\n' {
			l.advance()
		}
		return l.input[start:l.pos]
	}
	return ""
}

func (l *SQLLexer) isKeyword(s string) bool {
	upper := strings.ToUpper(s)
	for _, kw := range l.Keywords {
		if kw == upper {
			return true
		}
	}
	return false
}

func (l *SQLLexer) Tokenize() []*SQLToken {
	l.pos = 0
	l.tokens = make([]*SQLToken, 0)

	for !l.isAtEnd() {
		l.skipWhitespace()
		if l.isAtEnd() {
			break
		}

		start := l.pos
		ch := l.current()

		var tokenType TokenType
		var value string

		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' {
			value = l.readIdentifier()
			if l.isKeyword(value) {
				tokenType = TokenTypeKeyword
			} else {
				tokenType = TokenTypeIdentifier
			}
		} else if ch >= '0' && ch <= '9' {
			value = l.readNumber()
			tokenType = TokenTypeNumber
		} else if ch == '\'' || ch == '"' {
			value = l.readString(ch)
			tokenType = TokenTypeString
		} else if ch == '-' || (ch == '/' && l.peek() == '*') || ch == '#' {
			value = l.readComment()
			if value != "" {
				tokenType = TokenTypeComment
			} else {
				tokenType = TokenTypePunctuation
				value = string(ch)
				l.advance()
			}
		} else {
			switch ch {
			case '=':
				value = "="
				tokenType = TokenTypeOperator
				l.advance()
			case '<':
				if l.peek() == '=' {
					value = "<="
					l.advance()
					l.advance()
				} else if l.peek() == '>' {
					value = "<>"
					l.advance()
					l.advance()
				} else if l.peek() == '!' {
					value = "<!"
					l.advance()
					l.advance()
				} else {
					value = "<"
					tokenType = TokenTypeOperator
					l.advance()
				}
				if tokenType == TokenTypeUnknown {
					tokenType = TokenTypeOperator
				}
			case '>':
				if l.peek() == '=' {
					value = ">="
					l.advance()
					l.advance()
				} else {
					value = ">"
					tokenType = TokenTypeOperator
					l.advance()
				}
				if tokenType == TokenTypeUnknown {
					tokenType = TokenTypeOperator
				}
			case '!':
				if l.peek() == '=' {
					value = "!="
					l.advance()
					l.advance()
				} else {
					value = "!"
					tokenType = TokenTypeOperator
					l.advance()
				}
				if tokenType == TokenTypeUnknown {
					tokenType = TokenTypeOperator
				}
			case '+', '-', '*', '/', '%', '&', '|', '^':
				value = string(ch)
				tokenType = TokenTypeOperator
				l.advance()
			case '(', ')', ',', ';', '.':
				value = string(ch)
				tokenType = TokenTypePunctuation
				l.advance()
			default:
				value = string(ch)
				tokenType = TokenTypePunctuation
				l.advance()
			}
		}

		if value != "" {
			l.tokens = append(l.tokens, &SQLToken{
				Type:     tokenType,
				Value:    value,
				Position: start,
				Length:   len(value),
			})
		}
	}

	return l.tokens
}

type SQLParser struct {
	tokens   []*SQLToken
	pos      int
	ast      *SQLAST
}

func NewSQLParser(sql string) *SQLParser {
	lexer := NewSQLLexer(sql)
	tokens := lexer.Tokenize()
	return &SQLParser{
		tokens: tokens,
		pos:    0,
		ast:    NewSQLAST(sql),
	}
}

func (p *SQLParser) isAtEnd() bool {
	return p.pos >= len(p.tokens)
}

func (p *SQLParser) current() *SQLToken {
	if p.isAtEnd() {
		return nil
	}
	return p.tokens[p.pos]
}

func (p *SQLParser) peek() *SQLToken {
	if p.pos+1 >= len(p.tokens) {
		return nil
	}
	return p.tokens[p.pos+1]
}

func (p *SQLParser) advance() *SQLToken {
	if !p.isAtEnd() {
		p.pos++
	}
	return p.tokens[p.pos-1]
}

func (p *SQLParser) check(tokenType TokenType) bool {
	if p.isAtEnd() {
		return false
	}
	return p.current().Type == tokenType
}

func (p *SQLParser) checkKeyword(keyword string) bool {
	if p.isAtEnd() {
		return false
	}
	return strings.EqualFold(p.current().Value, keyword)
}

func (p *SQLParser) matchKeyword(keyword string) bool {
	if p.checkKeyword(keyword) {
		p.advance()
		return true
	}
	return false
}

func (p *SQLParser) matchAnyKeyword(keywords ...string) bool {
	for _, kw := range keywords {
		if p.checkKeyword(kw) {
			p.advance()
			return true
		}
	}
	return false
}

func (p *SQLParser) skipComments() {
	for !p.isAtEnd() && p.current().Type == TokenTypeComment {
		p.advance()
	}
}

func (p *SQLParser) parseStatement() *SQLNode {
	p.skipComments()
	if p.isAtEnd() {
		return nil
	}

	token := p.current()
	if token == nil {
		return nil
	}

	var stmt *SQLNode

	if strings.EqualFold(token.Value, "SELECT") || strings.EqualFold(token.Value, "SELECT/*") {
		stmt = p.parseSelect()
	} else if strings.EqualFold(token.Value, "INSERT") {
		stmt = p.parseInsert()
	} else if strings.EqualFold(token.Value, "UPDATE") {
		stmt = p.parseUpdate()
	} else if strings.EqualFold(token.Value, "DELETE") {
		stmt = p.parseDelete()
	} else if strings.EqualFold(token.Value, "DROP") {
		stmt = p.parseDrop()
	} else if strings.EqualFold(token.Value, "CREATE") {
		stmt = p.parseCreate()
	} else if strings.EqualFold(token.Value, "EXEC") || strings.EqualFold(token.Value, "EXECUTE") {
		stmt = p.parseExecute()
	} else if strings.EqualFold(token.Value, "DECLARE") {
		stmt = p.parseDeclare()
	} else if strings.EqualFold(token.Value, ";") {
		p.advance()
		return p.parseStatement()
	} else {
		p.advance()
		stmt = NewSQLNode(NodeTypeUnknown, token.Value)
	}

	return stmt
}

func (p *SQLParser) parseSelect() *SQLNode {
	node := NewSQLNode(NodeTypeSelect, "SELECT")
	startPos := p.current().Position

	if p.matchKeyword("SELECT") {
		for !p.isAtEnd() && !p.checkKeyword("FROM") && !p.checkKeyword("UNION") && !p.checkKeyword("WHERE") && !p.checkKeyword("GROUP") && !p.checkKeyword("ORDER") && !p.checkKeyword("LIMIT") && !p.checkKeyword(";") {
			p.skipComments()
			if p.isAtEnd() {
				break
			}
			if p.checkKeyword("FROM") || p.checkKeyword("UNION") {
				break
			}
			token := p.current()
			if token != nil {
				child := p.parseExpression()
				if child != nil {
					node.AddChild(child)
				}
			}
			if p.matchKeyword(",") {
				continue
			}
			break
		}

		if p.matchKeyword("FROM") {
			fromNode := NewSQLNode(NodeTypeFrom, "FROM")
			p.parseFromClause(fromNode)
			node.AddChild(fromNode)
		}

		if p.matchKeyword("WHERE") {
			whereNode := NewSQLNode(NodeTypeWhere, "WHERE")
			p.parseWhereClause(whereNode)
			node.AddChild(whereNode)
		}

		if p.matchKeyword("UNION") {
			unionNode := NewSQLNode(NodeTypeUnion, "UNION")
			if p.matchKeyword("ALL") {
				unionNode.Attributes["all"] = true
			}
			if p.matchKeyword("SELECT") || p.checkKeyword("SELECT") {
				childSelect := p.parseSelect()
				if childSelect != nil {
					unionNode.AddChild(childSelect)
				}
			}
			node.AddChild(unionNode)
		}

		if p.matchKeyword("GROUP") && p.matchKeyword("BY") {
			groupNode := NewSQLNode(NodeTypeGroupBy, "GROUP BY")
			p.parseGroupByClause(groupNode)
			node.AddChild(groupNode)
		}

		if p.matchKeyword("ORDER") && p.matchKeyword("BY") {
			orderNode := NewSQLNode(NodeTypeOrderBy, "ORDER BY")
			p.parseOrderByClause(orderNode)
			node.AddChild(orderNode)
		}

		if p.matchKeyword("LIMIT") {
			limitNode := NewSQLNode(NodeTypeLimit, "LIMIT")
			p.parseLimitClause(limitNode)
			node.AddChild(limitNode)
		}
	}

	node.RawText = p.ast.RawSQL[startPos:p.pos]
	return node
}

func (p *SQLParser) parseFromClause(node *SQLNode) {
	for !p.isAtEnd() && !p.checkKeyword("WHERE") && !p.checkKeyword("GROUP") && !p.checkKeyword("ORDER") && !p.checkKeyword("LIMIT") && !p.checkKeyword("UNION") && !p.checkKeyword(";") {
		p.skipComments()
		if p.isAtEnd() {
			break
		}
		if p.checkKeyword("WHERE") || p.checkKeyword("GROUP") || p.checkKeyword("ORDER") || p.checkKeyword("LIMIT") || p.checkKeyword("UNION") {
			break
		}

		token := p.current()
		if token != nil {
			if strings.EqualFold(token.Value, "JOIN") || strings.EqualFold(token.Value, "LEFT") || strings.EqualFold(token.Value, "RIGHT") || strings.EqualFold(token.Value, "INNER") || strings.EqualFold(token.Value, "OUTER") {
				joinNode := p.parseJoin()
				if joinNode != nil {
					node.AddChild(joinNode)
				}
			} else if p.checkKeyword("SELECT") {
				subquery := p.parseSelect()
				if subquery != nil {
					subquery.NodeType = NodeTypeSubquery
					node.AddChild(subquery)
				}
			} else {
				child := NewSQLNode(NodeTypeTable, token.Value)
				node.AddChild(child)
				p.advance()
			}
		}

		if p.matchKeyword(",") {
			continue
		}
		break
	}
}

func (p *SQLParser) parseJoin() *SQLNode {
	token := p.current()
	var joinType string

	if strings.EqualFold(token.Value, "LEFT") {
		if p.peek() != nil && strings.EqualFold(p.peek().Value, "JOIN") {
			p.advance()
			p.advance()
			joinType = "LEFT JOIN"
		} else if p.peek() != nil && strings.EqualFold(p.peek().Value, "OUTER") && p.peekNext() != nil && strings.EqualFold(p.peekNext().Value, "JOIN") {
			p.advance()
			p.advance()
			p.advance()
			joinType = "LEFT OUTER JOIN"
		}
	} else if strings.EqualFold(token.Value, "RIGHT") {
		if p.peek() != nil && strings.EqualFold(p.peek().Value, "JOIN") {
			p.advance()
			p.advance()
			joinType = "RIGHT JOIN"
		} else if p.peek() != nil && strings.EqualFold(p.peek().Value, "OUTER") && p.peekNext() != nil && strings.EqualFold(p.peekNext().Value, "JOIN") {
			p.advance()
			p.advance()
			p.advance()
			joinType = "RIGHT OUTER JOIN"
		}
	} else if strings.EqualFold(token.Value, "INNER") && p.peek() != nil && strings.EqualFold(p.peek().Value, "JOIN") {
		p.advance()
		p.advance()
		joinType = "INNER JOIN"
	} else if strings.EqualFold(token.Value, "JOIN") || strings.EqualFold(token.Value, "CROSS") && p.peek() != nil && strings.EqualFold(p.peek().Value, "JOIN") {
		if strings.EqualFold(token.Value, "CROSS") {
			p.advance()
		}
		p.advance()
		joinType = "CROSS JOIN"
	} else {
		joinType = "JOIN"
		p.advance()
	}

	joinNode := NewSQLNode(NodeTypeJoin, joinType)

	if !p.isAtEnd() && p.current().Type == TokenTypeIdentifier {
		tableNode := NewSQLNode(NodeTypeTable, p.current().Value)
		joinNode.AddChild(tableNode)
		p.advance()
	}

	if p.matchKeyword("ON") {
		onNode := NewSQLNode(NodeTypeCondition, "ON")
		p.parseCondition(onNode)
		joinNode.AddChild(onNode)
	}

	return joinNode
}

func (p *SQLParser) parseWhereClause(node *SQLNode) {
	depth := 0
	for !p.isAtEnd() && !(depth == 0 && (p.checkKeyword("GROUP") || p.checkKeyword("ORDER") || p.checkKeyword("LIMIT") || p.checkKeyword("UNION") || p.checkKeyword(";"))) {
		p.skipComments()
		if p.isAtEnd() {
			break
		}

		token := p.current()
		if token == nil {
			break
		}

		if token.Value == "(" {
			depth++
			p.advance()
			continue
		}
		if token.Value == ")" {
			depth--
			p.advance()
			if depth < 0 {
				break
			}
			continue
		}

		if depth == 0 && (p.checkKeyword("GROUP") || p.checkKeyword("ORDER") || p.checkKeyword("LIMIT") || p.checkKeyword("UNION") || p.checkKeyword(";")) {
			break
		}

		child := p.parseCondition(node)
		if child != nil {
			node.AddChild(child)
		}

		if p.matchKeyword("AND") || p.matchKeyword("OR") {
			continue
		}

		if depth == 0 && (p.checkKeyword("GROUP") || p.checkKeyword("ORDER") || p.checkKeyword("LIMIT") || p.checkKeyword("UNION")) {
			break
		}

		break
	}
}

func (p *SQLParser) parseCondition(parent *SQLNode) *SQLNode {
	if p.isAtEnd() {
		return nil
	}

	token := p.current()
	if token == nil {
		return nil
	}

	if p.checkKeyword("SELECT") {
		subquery := p.parseSelect()
		subquery.NodeType = NodeTypeSubquery
		return subquery
	}

	node := NewSQLNode(NodeTypeCondition, token.Value)

	if token.Type == TokenTypeKeyword || token.Type == TokenTypeIdentifier {
		if strings.EqualFold(token.Value, "EXISTS") || strings.EqualFold(token.Value, "NOT") {
			p.advance()
			if p.matchKeyword("EXISTS") {
				node.Value = token.Value + " EXISTS"
				if p.current() != nil && p.current().Value == "(" {
					p.advance()
					subquery := p.parseSelect()
					if subquery != nil {
						subquery.NodeType = NodeTypeSubquery
						node.AddChild(subquery)
					}
					if p.matchKeyword(")") {
					}
				}
			}
			return node
		}

		if strings.EqualFold(token.Value, "IN") || strings.EqualFold(token.Value, "NOT") && p.peek() != nil && strings.EqualFold(p.peek().Value, "IN") {
			if strings.EqualFold(token.Value, "NOT") {
				p.advance()
				p.advance()
				node.Value = "NOT IN"
			} else {
				p.advance()
				p.advance()
			}
			if p.current() != nil && p.current().Value == "(" {
				p.advance()
				for !p.isAtEnd() && p.current().Value != ")" {
					p.skipComments()
					if p.current().Value == ")" {
						break
					}
					valNode := NewSQLNode(NodeTypeValue, p.current().Value)
					node.AddChild(valNode)
					p.advance()
					if p.matchKeyword(",") {
						continue
					}
					break
				}
				if p.matchKeyword(")") {
				}
			}
			return node
		}
	}

	p.advance()

	if !p.isAtEnd() && (p.checkKeyword("=") || p.checkKeyword("<>") || p.checkKeyword("!=") || p.checkKeyword(">") || p.checkKeyword("<") || p.checkKeyword(">=") || p.checkKeyword("<=")) {
		op := p.current()
		p.advance()
		opNode := NewSQLNode(NodeTypeExpression, op.Value)
		opNode.AddChild(node)

		if !p.isAtEnd() {
			if p.checkKeyword("SELECT") {
				subquery := p.parseSelect()
				if subquery != nil {
					subquery.NodeType = NodeTypeSubquery
					opNode.AddChild(subquery)
				}
			} else if p.current() != nil {
				valNode := NewSQLNode(NodeTypeValue, p.current().Value)
				opNode.AddChild(valNode)
				p.advance()
			}
		}
		return opNode
	}

	return node
}

func (p *SQLParser) parseExpression() *SQLNode {
	if p.isAtEnd() {
		return nil
	}

	token := p.current()
	if token == nil {
		return nil
	}

	node := NewSQLNode(NodeTypeExpression, token.Value)

	if token.Type == TokenTypeString || token.Type == TokenTypeNumber {
		node.NodeType = NodeTypeValue
		p.advance()
		return node
	}

	if strings.EqualFold(token.Value, "SELECT") {
		selectNode := p.parseSelect()
		selectNode.NodeType = NodeTypeSubquery
		return selectNode
	}

	if strings.EqualFold(token.Value, "CASE") {
		p.advance()
		caseNode := NewSQLNode(NodeTypeExpression, "CASE")
		for !p.isAtEnd() && !p.checkKeyword("END") {
			whenNode := NewSQLNode(NodeTypeCondition, "WHEN")
			p.parseCondition(whenNode)
			if p.matchKeyword("THEN") {
				thenNode := NewSQLNode(NodeTypeValue, p.current().Value)
				whenNode.AddChild(thenNode)
				p.advance()
			}
			caseNode.AddChild(whenNode)
			if p.checkKeyword("END") {
				break
			}
		}
		if p.matchKeyword("END") {
		}
		return caseNode
	}

	p.advance()
	return node
}

func (p *SQLParser) parseGroupByClause(node *SQLNode) {
	for !p.isAtEnd() && !p.checkKeyword("HAVING") && !p.checkKeyword("ORDER") && !p.checkKeyword("LIMIT") && !p.checkKeyword("UNION") && !p.checkKeyword(";") {
		p.skipComments()
		if p.isAtEnd() {
			break
		}
		if p.checkKeyword("HAVING") || p.checkKeyword("ORDER") || p.checkKeyword("LIMIT") || p.checkKeyword("UNION") {
			break
		}
		token := p.current()
		if token != nil && token.Type != TokenTypePunctuation && token.Value != "," {
			colNode := NewSQLNode(NodeTypeColumn, token.Value)
			node.AddChild(colNode)
			p.advance()
		}
		if p.matchKeyword(",") {
			continue
		}
		break
	}
}

func (p *SQLParser) parseOrderByClause(node *SQLNode) {
	for !p.isAtEnd() && !p.checkKeyword("LIMIT") && !p.checkKeyword(";") {
		p.skipComments()
		if p.isAtEnd() || p.checkKeyword("LIMIT") {
			break
		}
		token := p.current()
		if token != nil && token.Type != TokenTypePunctuation && token.Value != "," {
			colNode := NewSQLNode(NodeTypeColumn, token.Value)
			node.AddChild(colNode)
			p.advance()
			if p.checkKeyword("ASC") || p.checkKeyword("DESC") {
				p.advance()
			}
		}
		if p.matchKeyword(",") {
			continue
		}
		break
	}
}

func (p *SQLParser) parseLimitClause(node *SQLNode) {
	for !p.isAtEnd() && !p.checkKeyword(";") && !p.checkKeyword("UNION") {
		p.skipComments()
		if p.isAtEnd() {
			break
		}
		token := p.current()
		if token != nil {
			valNode := NewSQLNode(NodeTypeValue, token.Value)
			node.AddChild(valNode)
			p.advance()
		}
		if p.matchKeyword(",") {
			continue
		}
		if p.checkKeyword("OFFSET") {
			p.advance()
			continue
		}
		break
	}
}

func (p *SQLParser) parseInsert() *SQLNode {
	node := NewSQLNode(NodeTypeInsert, "INSERT")
	p.advance()

	if p.matchKeyword("INTO") {
		node.Value = "INSERT INTO"
	}

	for !p.isAtEnd() && !p.checkKeyword("VALUES") && !p.checkKeyword("SELECT") && !p.checkKeyword(";") {
		p.skipComments()
		if p.isAtEnd() {
			break
		}
		token := p.current()
		if token != nil && token.Type == TokenTypeIdentifier {
			colNode := NewSQLNode(NodeTypeColumn, token.Value)
			node.AddChild(colNode)
			p.advance()
		}
		if p.matchKeyword(",") {
			continue
		}
		if p.checkKeyword("VALUES") || p.checkKeyword("SELECT") {
			break
		}
		break
	}

	if p.matchKeyword("VALUES") || p.matchKeyword("VALUE") {
		valuesNode := NewSQLNode(NodeTypeValue, "VALUES")
		for !p.isAtEnd() && !p.checkKeyword(";") {
			p.skipComments()
			if p.isAtEnd() {
				break
			}
			if p.current().Value == "(" {
				p.advance()
				for !p.isAtEnd() && p.current().Value != ")" {
					token := p.current()
					if token != nil {
						valNode := NewSQLNode(NodeTypeValue, token.Value)
						valuesNode.AddChild(valNode)
						p.advance()
					}
					if p.matchKeyword(",") {
						continue
					}
					if p.current().Value == ")" {
						break
					}
				}
				if p.matchKeyword(")") {
				}
			}
			if p.matchKeyword(",") {
				continue
			}
			if p.checkKeyword(";") {
				break
			}
			break
		}
		node.AddChild(valuesNode)
	}

	return node
}

func (p *SQLParser) parseUpdate() *SQLNode {
	node := NewSQLNode(NodeTypeUpdate, "UPDATE")
	p.advance()

	if !p.isAtEnd() && p.current().Type == TokenTypeIdentifier {
		tableNode := NewSQLNode(NodeTypeTable, p.current().Value)
		node.AddChild(tableNode)
		p.advance()
	}

	if p.matchKeyword("SET") {
		setNode := NewSQLNode(NodeTypeExpression, "SET")
		for !p.isAtEnd() && !p.checkKeyword("WHERE") && !p.checkKeyword(";") {
			p.skipComments()
			if p.isAtEnd() {
				break
			}
			token := p.current()
			if token != nil && token.Type == TokenTypeIdentifier {
				colNode := NewSQLNode(NodeTypeColumn, token.Value)
				setNode.AddChild(colNode)
				p.advance()
				if p.matchKeyword("=") {
					valNode := p.parseExpression()
					if valNode != nil {
						setNode.AddChild(valNode)
					}
				}
			}
			if p.matchKeyword(",") {
				continue
			}
			if p.checkKeyword("WHERE") {
				break
			}
			break
		}
		node.AddChild(setNode)
	}

	if p.matchKeyword("WHERE") {
		whereNode := NewSQLNode(NodeTypeWhere, "WHERE")
		p.parseWhereClause(whereNode)
		node.AddChild(whereNode)
	}

	return node
}

func (p *SQLParser) parseDelete() *SQLNode {
	node := NewSQLNode(NodeTypeDelete, "DELETE")
	p.advance()

	if p.matchKeyword("FROM") {
		node.Value = "DELETE FROM"
	}

	if !p.isAtEnd() && p.current().Type == TokenTypeIdentifier {
		tableNode := NewSQLNode(NodeTypeTable, p.current().Value)
		node.AddChild(tableNode)
		p.advance()
	}

	if p.matchKeyword("WHERE") {
		whereNode := NewSQLNode(NodeTypeWhere, "WHERE")
		p.parseWhereClause(whereNode)
		node.AddChild(whereNode)
	}

	return node
}

func (p *SQLParser) parseDrop() *SQLNode {
	node := NewSQLNode(NodeTypeDrop, "DROP")
	p.advance()

	if p.matchAnyKeyword("TABLE", "DATABASE", "INDEX", "VIEW", "PROCEDURE", "FUNCTION", "TRIGGER") {
		node.Value = "DROP " + p.tokens[p.pos-1].Value
	}

	if !p.isAtEnd() && p.current().Type == TokenTypeIdentifier {
		nameNode := NewSQLNode(NodeTypeTable, p.current().Value)
		node.AddChild(nameNode)
		p.advance()
	}

	return node
}

func (p *SQLParser) parseCreate() *SQLNode {
	node := NewSQLNode(NodeTypeCreate, "CREATE")
	p.advance()

	if p.matchAnyKeyword("TABLE", "DATABASE", "INDEX", "VIEW", "PROCEDURE", "FUNCTION", "TRIGGER") {
		node.Value = "CREATE " + p.tokens[p.pos-1].Value
	}

	return node
}

func (p *SQLParser) parseExecute() *SQLNode {
	node := NewSQLNode(NodeTypeExecute, "EXEC")
	p.advance()

	if p.matchKeyword("(") {
		for !p.isAtEnd() && p.current().Value != ")" {
			token := p.current()
			if token != nil {
				child := NewSQLNode(NodeTypeExpression, token.Value)
				node.AddChild(child)
				p.advance()
			}
			if p.matchKeyword(",") {
				continue
			}
		}
		if p.matchKeyword(")") {
		}
	} else {
		for !p.isAtEnd() && !p.checkKeyword(";") {
			p.skipComments()
			if p.isAtEnd() {
				break
			}
			token := p.current()
			if token != nil {
				child := p.parseExpression()
				if child != nil {
					node.AddChild(child)
				}
			}
			if p.checkKeyword(";") {
				break
			}
			break
		}
	}

	return node
}

func (p *SQLParser) parseDeclare() *SQLNode {
	node := NewSQLNode(NodeTypeUnknown, "DECLARE")
	p.advance()

	for !p.isAtEnd() && !p.checkKeyword(";") {
		p.skipComments()
		if p.isAtEnd() {
			break
		}
		token := p.current()
		if token != nil {
			child := NewSQLNode(NodeTypeExpression, token.Value)
			node.AddChild(child)
			p.advance()
		}
		if p.checkKeyword(";") {
			break
		}
		break
	}

	return node
}

func (p *SQLParser) Parse() *SQLAST {
	p.pos = 0

	for !p.isAtEnd() {
		stmt := p.parseStatement()
		if stmt != nil {
			p.ast.Statements = append(p.ast.Statements, stmt)
		}
		if p.isAtEnd() {
			break
		}
		if p.matchKeyword(";") {
			continue
		}
	}

	p.ast.Root = p.ast.Statements[0]
	if len(p.ast.Statements) > 0 {
		p.ast.Root = NewSQLNode(NodeTypeUnknown, "STATEMENTS")
		for _, stmt := range p.ast.Statements {
			p.ast.Root.AddChild(stmt)
		}
	}

	return p.ast
}

type SQLSemanticAnalyzer struct {
	name         string
	version      string
	analyzerType string
	enabled      bool
	config       map[string]interface{}
	mu           sync.RWMutex
	patternCache *PatternCache
}

func NewSQLSemanticAnalyzer() *SQLSemanticAnalyzer {
	return &SQLSemanticAnalyzer{
		name:         "sql_semantic_analyzer",
		version:      "3.0.0",
		analyzerType: "sql_injection_semantic",
		enabled:      true,
		config:       make(map[string]interface{}),
		patternCache: NewPatternCache(),
	}
}

func (a *SQLSemanticAnalyzer) Name() string {
	return a.name
}

func (a *SQLSemanticAnalyzer) Type() string {
	return a.analyzerType
}

func (a *SQLSemanticAnalyzer) Version() string {
	return a.version
}

func (a *SQLSemanticAnalyzer) IsEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enabled
}

func (a *SQLSemanticAnalyzer) SetEnabled(enabled bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = enabled
}

func (a *SQLSemanticAnalyzer) Configure(config map[string]interface{}) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.config = config
	return nil
}

func (a *SQLSemanticAnalyzer) Analyze(input *AnalysisInput) *AnalysisResult {
	start := time.Now()
	result := NewAnalysisResult(a)

	if input == nil || input.Raw == "" {
		return result
	}

	rawData := input.Raw
	if input.QueryString != "" {
		rawData += " " + input.QueryString
	}
	if input.Body != "" {
		rawData += " " + input.Body
	}

	ast := NewSQLParser(rawData).Parse()

	a.detectUnionInjection(ast, result)
	a.detectBooleanBlindInjection(ast, result)
	a.detectTimeBlindInjection(rawData, result)
	a.detectErrorBasedInjection(rawData, result)
	a.detectStackedInjection(rawData, result)
	a.detectCommentObfuscation(rawData, result)
	a.detectDataModification(ast, result)
	a.detectPrivilegeEscalation(ast, result)
	a.detectMaliciousStructure(ast, result)

	result.ProcessingTime = time.Since(start)

	if len(result.Matches) > 0 {
		result.ShouldBlock = result.ShouldBlockRequest(0.6)
		result.ShouldLog = true
		result.ShouldAllow = !result.ShouldBlock
	}

	return result
}

func (a *SQLSemanticAnalyzer) detectUnionInjection(ast *SQLAST, result *AnalysisResult) {
	for _, stmt := range ast.Statements {
		if a.hasUnionNode(stmt) {
			unionSelectCount := a.countUnionSelectColumns(stmt)
			if unionSelectCount > 0 && unionSelectCount < 3 {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelHigh,
					Pattern:        "UNION SELECT with few columns",
					Description:    "UNION注入 - 尝试提取数据",
					Recommendation: "验证输入参数，限制UNION关键字",
				})
			} else if unionSelectCount >= 3 {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelMedium,
					Pattern:        "UNION SELECT with multiple columns",
					Description:    "UNION注入 - 多列数据提取",
					Recommendation: "检查是否有敏感数据泄露风险",
				})
			}

			if a.hasSubqueryInUnion(stmt) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelHigh,
					Pattern:        "UNION with subquery",
					Description:    "UNION子查询注入",
					Recommendation: "阻止包含子查询的UNION语句",
				})
			}

			if a.checkIntoOutfile(stmt) {
				result.AddMatch(Match{
					Type:           MatchTypeSemantic,
					ThreatLevel:    ThreatLevelCritical,
					Pattern:        "UNION SELECT INTO OUTFILE/DUMPFILE",
					Description:    "UNION文件写入攻击",
					Recommendation: "立即阻止并记录安全事件",
				})
				result.ShouldBlock = true
				result.ShouldAllow = false
			}
		}
	}
}

func (a *SQLSemanticAnalyzer) hasUnionNode(node *SQLNode) bool {
	if node == nil {
		return false
	}
	if node.NodeType == NodeTypeUnion {
		return true
	}
	for _, child := range node.Children {
		if a.hasUnionNode(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) countUnionSelectColumns(node *SQLNode) int {
	count := 0
	if node.NodeType == NodeTypeSelect {
		for _, child := range node.Children {
			if child.NodeType == NodeTypeFrom {
				for _, fromChild := range child.Children {
					if fromChild.NodeType == NodeTypeColumn || fromChild.NodeType == NodeTypeValue {
						count++
					}
				}
			}
		}
	}
	for _, child := range node.Children {
		count += a.countUnionSelectColumns(child)
	}
	return count
}

func (a *SQLSemanticAnalyzer) hasSubqueryInUnion(node *SQLNode) bool {
	if node == nil {
		return false
	}
	if node.NodeType == NodeTypeUnion {
		for _, child := range node.Children {
			if a.containsSubquery(child) {
				return true
			}
		}
	}
	for _, child := range node.Children {
		if a.hasSubqueryInUnion(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) containsSubquery(node *SQLNode) bool {
	if node == nil {
		return false
	}
	if node.NodeType == NodeTypeSubquery {
		return true
	}
	for _, child := range node.Children {
		if a.containsSubquery(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) checkIntoOutfile(node *SQLNode) bool {
	if node == nil {
		return false
	}
	raw := strings.ToUpper(node.RawText)
	if strings.Contains(raw, "INTO") && (strings.Contains(raw, "OUTFILE") || strings.Contains(raw, "DUMPFILE")) {
		return true
	}
	for _, child := range node.Children {
		if a.checkIntoOutfile(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) detectBooleanBlindInjection(ast *SQLAST, result *AnalysisResult) {
	for _, stmt := range ast.Statements {
		if a.hasBooleanBlindPattern(stmt) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "Boolean blind injection pattern",
				Description:    "布尔盲注 - 基于真假判断的信息泄露",
				Recommendation: "验证输入参数，阻止OR/AND条件注入",
			})
		}

		if a.hasExistsPattern(stmt) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "EXISTS subquery pattern",
				Description:    "EXISTS型盲注 - 条件判断攻击",
				Recommendation: "过滤EXISTS和子查询组合",
			})
		}

		if a.hasCaseWhenPattern(stmt) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "CASE WHEN pattern",
				Description:    "CASE WHEN盲注 - 条件推理攻击",
				Recommendation: "阻止CASE WHEN表达式注入",
			})
		}
	}
}

func (a *SQLSemanticAnalyzer) hasBooleanBlindPattern(node *SQLNode) bool {
	if node == nil {
		return false
	}

	if node.NodeType == NodeTypeCondition {
		condStr := strings.ToUpper(node.Value)
		if strings.Contains(condStr, "AND") || strings.Contains(condStr, "OR") {
			for _, child := range node.Children {
				if child.NodeType == NodeTypeExpression {
					exprStr := strings.ToUpper(child.RawText)
					if matched, _ := regexp.MatchString(`\d+\s*=\s*\d+`, exprStr); matched {
						return true
					}
					if matched, _ := regexp.MatchString(`'\w+'\s*=\s*'\w+'`, exprStr); matched {
						return true
					}
				}
			}
		}
	}

	for _, child := range node.Children {
		if a.hasBooleanBlindPattern(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) hasExistsPattern(node *SQLNode) bool {
	if node == nil {
		return false
	}

	if strings.Contains(strings.ToUpper(node.Value), "EXISTS") {
		return true
	}

	for _, child := range node.Children {
		if a.hasExistsPattern(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) hasCaseWhenPattern(node *SQLNode) bool {
	if node == nil {
		return false
	}

	if strings.Contains(strings.ToUpper(node.Value), "CASE") {
		return true
	}

	for _, child := range node.Children {
		if a.hasCaseWhenPattern(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) detectTimeBlindInjection(data string, result *AnalysisResult) {
	criticalPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bSLEEP\s*\(\s*[5-9]\d*\s*\)`, "高延迟时间盲注 - 活跃攻击", ThreatLevelCritical},
		{`(?i)\bBENCHMARK\s*\(\s*[5-9]\d{2,}`, "高延迟BENCHMARK攻击", ThreatLevelCritical},
		{`(?i)\bWAITFOR\s+DELAY\s+'[^']*[5-9]\d+`, "高延迟WAITFOR攻击", ThreatLevelCritical},
		{`(?i)\bREPEAT\s*\(\s*[^)]+,\s*[5-9]\d{3,}\s*\)`, "高延迟REPEAT攻击", ThreatLevelCritical},
		{`(?i)\bPG_SLEEP\s*\(\s*[5-9]\d*\s*\)`, "PostgreSQL高延迟攻击", ThreatLevelCritical},
		{`(?i)\bSLEEP\s*\(\s*[1-4]\d*\s*\)`, "中延迟时间盲注", ThreatLevelHigh},
		{`(?i)\bBENCHMARK\s*\(\s*[1-4]\d{2,}`, "中延迟BENCHMARK攻击", ThreatLevelHigh},
		{`(?i)\bWAITFOR\s+DELAY\s+'[^']*[1-4]\d+`, "中延迟WAITFOR攻击", ThreatLevelHigh},
		{`(?i)\bSLEEP\s*\(\s*\d+\s*\)`, "基础时间盲注", ThreatLevelMedium},
		{`(?i)\bBENCHMARK\s*\(`, "BENCHMARK函数注入", ThreatLevelMedium},
		{`(?i)\bWAITFOR\s+DELAY\b`, "WAITFOR延迟攻击", ThreatLevelMedium},
		{`(?i)\bPG_SLEEP\b`, "PostgreSQL时间盲注", ThreatLevelMedium},
		{`(?i)\bDBMS_PIPE\.RECEIVE_MESSAGE\b`, "Oracle时间盲注", ThreatLevelMedium},
		{`(?i)\bRLIKE\s+\w+\s*\(`, "RLIKE时间延迟", ThreatLevelMedium},
	}

	for _, p := range criticalPatterns {
		re := a.patternCache.GetMust(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "立即阻止请求并记录日志",
			})

			if p.threatLevel >= ThreatLevelCritical {
				result.ShouldBlock = true
				result.ShouldAllow = false
				return
			}
		}
	}
}

func (a *SQLSemanticAnalyzer) detectErrorBasedInjection(data string, result *AnalysisResult) {
	errorPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)\bEXTRACTVALUE\s*\([^,]+,[^)]+\)`, "EXTRACTVALUE报错注入", ThreatLevelHigh},
		{`(?i)\bUPDATEXML\s*\([^,]+,[^,]+,[^)]+\)`, "UPDATEXML报错注入", ThreatLevelHigh},
		{`(?i)\bEXTRACTVALUE\s*\(`, "XML函数报错注入", ThreatLevelMedium},
		{`(?i)\bUPDATEXML\s*\(`, "XML函数报错注入", ThreatLevelMedium},
		{`(?i)\bXMLTYPE\s*\([^)]+\)`, "XMLTYPE报错注入", ThreatLevelMedium},
		{`(?i)\bDBMS_XMLGEN\.GETXML\s*\(`, "DBMS_XMLGEN报错注入", ThreatLevelMedium},
		{`(?i)\bCTXSYS\.DRITHX\.SN1\b`, "CTXSYS报错注入", ThreatLevelMedium},
		{`(?i)\bCTXSYS\.DRITHX\.SN\b`, "CTXSYS报错注入", ThreatLevelMedium},
		{`(?i)\bORD\([^)]+\)\s*=\s*\d+`, "ORD()函数攻击", ThreatLevelMedium},
		{`(?i)\bEXISTS\s*\(\s*SELECT\b`, "EXISTS子查询注入", ThreatLevelMedium},
		{`(?i)\bNOT\s+EXISTS\s*\(\s*SELECT\b`, "NOT EXISTS注入", ThreatLevelMedium},
		{`(?i)\bCOUNT\s*\(\s*SELECT\b`, "COUNT子查询注入", ThreatLevelMedium},
		{`(?i)\bEXISTS\s*\(\s*SELECT\s+\d+\s+FROM\b`, "简化EXISTS注入检测", ThreatLevelLow},
		{`(?i)')\s*(AND|OR)\s*\d+\s*=\s*\d+`, "通用报错注入模式", ThreatLevelMedium},
		{`(?i)\bEXTRACTVALUE\b`, "XML提取函数注入", ThreatLevelMedium},
		{`(?i)\bUPDATEXML\b`, "XML更新函数注入", ThreatLevelMedium},
	}

	for _, p := range errorPatterns {
		re := a.patternCache.GetMust(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "阻止报错函数注入攻击",
			})
		}
	}
}

func (a *SQLSemanticAnalyzer) detectStackedInjection(data string, result *AnalysisResult) {
	stackedPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i);\s*DROP\s+(TABLE|DATABASE|INDEX)`, "DROP堆叠注入 - 毁灭性攻击", ThreatLevelCritical},
		{`(?i);\s*DELETE\s+FROM`, "DELETE堆叠注入 - 数据删除", ThreatLevelCritical},
		{`(?i);\s*TRUNCATE\s+`, "TRUNCATE堆叠注入", ThreatLevelCritical},
		{`(?i);\s*ALTER\s+(DATABASE|TABLE)`, "ALTER堆叠注入 - 结构修改", ThreatLevelCritical},
		{`(?i);\s*GRANT\s+`, "GRANT堆叠注入 - 权限提升", ThreatLevelCritical},
		{`(?i);\s*REVOKE\s+`, "REVOKE堆叠注入 - 权限撤销", ThreatLevelCritical},
		{`(?i);\s*DENY\s+`, "DENY堆叠注入 - 权限拒绝", ThreatLevelCritical},
		{`(?i);\s*CREATE\s+(TABLE|DATABASE|PROCEDURE|FUNCTION|TRIGGER)`, "CREATE堆叠注入 - 创建对象", ThreatLevelHigh},
		{`(?i);\s*INSERT\s+INTO`, "INSERT堆叠注入 - 数据插入", ThreatLevelHigh},
		{`(?i);\s*UPDATE\s+`, "UPDATE堆叠注入 - 数据修改", ThreatLevelHigh},
		{`(?i);\s*EXEC\s*\(?\s*@`, "EXEC堆叠注入 - 动态执行", ThreatLevelHigh},
		{`(?i);\s*EXECUTE\s+\(?\s*@`, "EXECUTE堆叠注入", ThreatLevelHigh},
		{`(?i);\s*XP_CMDSHELL`, "XP_CMDSHELL堆叠注入 - 系统命令", ThreatLevelCritical},
		{`(?i);\s*SP_EXECUTESQL`, "SP_EXECUTESQL堆叠注入", ThreatLevelHigh},
		{`(?i);\s*OPENROWSET`, "OPENROWSET堆叠注入", ThreatLevelHigh},
		{`(?i);\s*OPENDATASOURCE`, "OPENDATASOURCE堆叠注入", ThreatLevelHigh},
		{`(?i);\s*LOAD\s+FILE`, "LOAD FILE堆叠注入 - 文件读取", ThreatLevelHigh},
		{`(?i);\s*INTO\s+(OUT|DUMP)FILE`, "文件导出堆叠注入", ThreatLevelCritical},
		{`(?i);\s*SHUTDOWN\s+`, "SHUTDOWN堆叠注入 - 数据库关闭", ThreatLevelCritical},
		{`(?i);\s*KILL\s+`, "KILL堆叠注入 - 进程终止", ThreatLevelHigh},
		{`(?i);\s*DECLARE\s+@\w+\s+VARCHAR`, "DECLARE堆叠注入 - 变量声明", ThreatLevelHigh},
		{`(?i);?\s*--\s*$`, "SQL注释注入 - 语句截断", ThreatLevelMedium},
		{`(?i);?\s*#\s*$`, "SQL注释注入 - 语句截断", ThreatLevelMedium},
		{`(?i);\s*SELECT\b`, "SELECT堆叠注入", ThreatLevelMedium},
	}

	for _, p := range stackedPatterns {
		re := a.patternCache.GetMust(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "阻止堆叠查询注入攻击",
			})

			if p.threatLevel >= ThreatLevelCritical {
				result.ShouldBlock = true
				result.ShouldAllow = false
				return
			}
		}
	}
}

func (a *SQLSemanticAnalyzer) detectCommentObfuscation(data string, result *AnalysisResult) {
	commentPatterns := []struct {
		pattern     string
		description string
		threatLevel ThreatLevel
	}{
		{`(?i)/\*.*?\*/`, "内联注释注入 - 混淆绕过", ThreatLevelMedium},
		{`(?i)/\*\s*!\s*\d+\s*.*?\*/`, "MySQL条件注释注入", ThreatLevelMedium},
		{`(?i)/\*\s*-\s*\*/`, "空注释混淆", ThreatLevelLow},
		{`(?i)/\*\s*\*/`, "垃圾注释混淆", ThreatLevelLow},
		{`(?i)'--\s*$`, "单行注释截断 - OR攻击", ThreatLevelHigh},
		{`(?i)'#\s*$`, "Hash注释截断", ThreatLevelHigh},
		{`(?i)'/\*`, "注释开始截断", ThreatLevelMedium},
		{`(?i)';\s*--`, "组合截断攻击", ThreatLevelHigh},
		{`(?i)';\s*#`, "组合截断攻击", ThreatLevelHigh},
		{`(?i)'\s*OR\s+'1'\s*=\s*'1'\s*--`, "经典OR永真式注释攻击", ThreatLevelCritical},
		{`(?i)'\s*OR\s+'1'\s*=\s*'1'\s*#`, "经典OR永真式Hash攻击", ThreatLevelCritical},
		{`(?i)admin'\s*--`, "管理员绕过注释攻击", ThreatLevelCritical},
		{`(?i)admin'\s*#`, "管理员绕过Hash攻击", ThreatLevelCritical},
		{`(?i)'\s*OR\s+'[^']+'\s*=\s*'[^']+`, "通用OR注入", ThreatLevelHigh},
		{`(?i)"\s*OR\s*"1"\s*=\s*"1"`, "双引号OR注入", ThreatLevelHigh},
		{`(?i)` + "\x00" + `.*`, "空字节注入截断", ThreatLevelHigh},
		{`(?i)')\s*OR\s*\(\s*1\s*=\s*1\s*\)`, "括号OR注入", ThreatLevelHigh},
		{`(?i)'\s+OR\s+'1'='1'`, "空格分隔OR注入", ThreatLevelHigh},
	}

	for _, p := range commentPatterns {
		re := a.patternCache.GetMust(p.pattern)
		if re.MatchString(data) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    p.threatLevel,
				Pattern:        p.pattern,
				Description:    p.description,
				Recommendation: "过滤注释字符和OR条件组合",
			})
		}
	}
}

func (a *SQLSemanticAnalyzer) detectDataModification(ast *SQLAST, result *AnalysisResult) {
	for _, stmt := range ast.Statements {
		if a.isDangerousModification(stmt) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        "Dangerous data modification",
				Description:    "数据变指令攻击 - SELECT被替换为危险操作",
				Recommendation: "立即阻止并通知安全团队",
			})
			result.ShouldBlock = true
			result.ShouldAllow = false
			return
		}

		if a.hasOr1Equals1(stmt) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        "OR 1=1 pattern",
				Description:    "永真式SQL注入 - 所有记录被影响",
				Recommendation: "阻止OR 1=1类型的注入",
			})
			result.ShouldBlock = true
			result.ShouldAllow = false
			return
		}
	}
}

func (a *SQLSemanticAnalyzer) isDangerousModification(node *SQLNode) bool {
	if node == nil {
		return false
	}

	if node.NodeType == NodeTypeDelete || node.NodeType == NodeTypeDrop || node.NodeType == NodeTypeTruncate {
		return true
	}

	if node.NodeType == NodeTypeUpdate {
		return a.hasOr1Equals1(node)
	}

	for _, child := range node.Children {
		if a.isDangerousModification(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) hasOr1Equals1(node *SQLNode) bool {
	if node == nil {
		return false
	}

	raw := strings.ToUpper(node.RawText)
	if matched, _ := regexp.MatchString(`OR\s+1\s*=\s*1`, raw); matched {
		return true
	}
	if matched, _ := regexp.MatchString(`OR\s+TRUE`, raw); matched {
		return true
	}
	if matched, _ := regexp.MatchString(`OR\s+'?\s*=\s*'?`, raw); matched {
		return true
	}

	for _, child := range node.Children {
		if a.hasOr1Equals1(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) detectPrivilegeEscalation(ast *SQLAST, result *AnalysisResult) {
	for _, stmt := range ast.Statements {
		if a.containsPrivilegeEscalation(stmt) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelCritical,
				Pattern:        "Privilege escalation attempt",
				Description:    "权限提升攻击 - 尝试获取管理员凭据",
				Recommendation: "立即阻止并启用最高级别告警",
			})
			result.ShouldBlock = true
			result.ShouldAllow = false
			return
		}
	}
}

func (a *SQLSemanticAnalyzer) containsPrivilegeEscalation(node *SQLNode) bool {
	if node == nil {
		return false
	}

	raw := strings.ToUpper(node.RawText)

	privilegeKeywords := []string{
		"USER", "PASSWORD", "PASSWD", "CREDS", "CREDENTIAL",
		"ADMIN", "ROOT", "SUPER", "PRIVILEGE", "ROLE",
		"SESSION_USER", "CURRENT_USER", "LOAD_FILE",
	}

	keywordCount := 0
	for _, kw := range privilegeKeywords {
		if strings.Contains(raw, kw) {
			keywordCount++
		}
	}

	if keywordCount >= 2 {
		return true
	}

	for _, child := range node.Children {
		if a.containsPrivilegeEscalation(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) detectMaliciousStructure(ast *SQLAST, result *AnalysisResult) {
	for _, stmt := range ast.Statements {
		if a.hasMaliciousOrderBy(stmt) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelMedium,
				Pattern:        "Malicious ORDER BY injection",
				Description:    "ORDER BY注入 - 可能的UNION攻击前奏",
				Recommendation: "验证ORDER BY参数为数字",
			})
		}

		if a.hasIllegalOrCondition(stmt) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        "Illegal OR condition",
				Description:    "非法OR条件 - 典型的注入特征",
				Recommendation: "阻止OR条件后的复杂表达式",
			})
		}

		if a.hasUnionOrderBy(stmt) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        "UNION with ORDER BY",
				Description:    "UNION + ORDER BY组合攻击",
				Recommendation: "阻止UNION和ORDER BY的组合",
			})
		}

		if a.hasUnionGroupBy(stmt) {
			result.AddMatch(Match{
				Type:           MatchTypeSemantic,
				ThreatLevel:    ThreatLevelHigh,
				Pattern:        "UNION with GROUP BY",
				Description:    "UNION + GROUP BY组合攻击",
				Recommendation: "阻止UNION和GROUP BY的组合",
			})
		}
	}
}

func (a *SQLSemanticAnalyzer) hasMaliciousOrderBy(node *SQLNode) bool {
	if node == nil {
		return false
	}

	if node.NodeType == NodeTypeOrderBy {
		if len(node.Children) > 3 {
			return true
		}
		for _, child := range node.Children {
			if child.NodeType == NodeTypeExpression && strings.Contains(strings.ToUpper(child.Value), "SELECT") {
				return true
			}
		}
	}

	for _, child := range node.Children {
		if a.hasMaliciousOrderBy(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) hasIllegalOrCondition(node *SQLNode) bool {
	if node == nil {
		return false
	}

	if node.NodeType == NodeTypeCondition {
		raw := strings.ToUpper(node.RawText)
		if strings.Contains(raw, "OR") {
			if matched, _ := regexp.MatchString(`OR\s+['"]?\s*\d+\s*=`, raw); matched {
				return true
			}
			if matched, _ := regexp.MatchString(`OR\s+['"]?\s*[a-zA-Z]+\s*=`, raw); matched {
				return true
			}
		}
	}

	for _, child := range node.Children {
		if a.hasIllegalOrCondition(child) {
			return true
		}
	}
	return false
}

func (a *SQLSemanticAnalyzer) hasUnionOrderBy(node *SQLNode) bool {
	hasUnion := false
	hasOrderBy := false

	var traverse func(n *SQLNode)
	traverse = func(n *SQLNode) {
		if n == nil {
			return
		}
		if n.NodeType == NodeTypeUnion {
			hasUnion = true
		}
		if n.NodeType == NodeTypeOrderBy {
			hasOrderBy = true
		}
		for _, child := range n.Children {
			traverse(child)
		}
	}

	traverse(node)
	return hasUnion && hasOrderBy
}

func (a *SQLSemanticAnalyzer) hasUnionGroupBy(node *SQLNode) bool {
	hasUnion := false
	hasGroupBy := false

	var traverse func(n *SQLNode)
	traverse = func(n *SQLNode) {
		if n == nil {
			return
		}
		if n.NodeType == NodeTypeUnion {
			hasUnion = true
		}
		if n.NodeType == NodeTypeGroupBy {
			hasGroupBy = true
		}
		for _, child := range n.Children {
			traverse(child)
		}
	}

	traverse(node)
	return hasUnion && hasGroupBy
}

func ParseSQL(sql string) *SQLAST {
	parser := NewSQLParser(sql)
	return parser.Parse()
}

func AnalyzeSQL(sql string) *AnalysisResult {
	analyzer := NewSQLSemanticAnalyzer()
	input := &AnalysisInput{
		Raw:         sql,
		QueryString: "",
		Body:        "",
	}
	return analyzer.Analyze(input)
}
