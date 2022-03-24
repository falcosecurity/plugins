/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"github.com/pingcap/parser"
	"github.com/pingcap/parser/ast"
	"github.com/pingcap/parser/mysql"
	_ "github.com/pingcap/parser/test_driver"
)

type queryFields struct {
	IsSelect    bool
	IsSet       bool
	IsCreate    bool
	IsDrop      bool
	IsUpdate    bool
	IsInsert    bool
	IsGrant     bool
	IsRevoke    bool
	IsAlter     bool
	IsDelete    bool
	SetArgs     []string
	DropArgs    []string
	Select      []string
	Join        []string
	Where       []string
	CreateLoc   []string
	CreateArgs  []string
	UpdateArgs  []string
	InsertClmns []string
	InsertTable []string
	GrantArgs   []string
	GrantUSR    []string
	RevokeUSR   []string
	RevokeArgs  []string
	AlterTable  []string
	AlterSpec   []string
	DeleteTable []string
}

func (res *queryFields) Enter(in ast.Node) (ast.Node, bool) {
	switch n := in.(type) {
	case *ast.SelectStmt:
		res.IsSelect = true
	case *ast.SelectField:
		res.Select = append(res.Select, n.Text())
	case *ast.SetStmt:
		res.IsSet = true
		res.SetArgs = append(res.SetArgs, n.Text())
	case *ast.Join:
		//TODO catch FROM/JOIN
	case *ast.CreateTableStmt:
		res.IsCreate = true
		if n.Select != nil {
			res.CreateLoc = append(res.CreateLoc, n.Select.Text())
		}
		if n.Table != nil {
			res.CreateArgs = append(res.CreateArgs, n.Table.Name.String())
		}
	case *ast.DropTableStmt:
		res.IsDrop = true
		for _, k := range n.Tables {
			res.DropArgs = append(res.DropArgs, k.Name.String())
		}
	case *ast.UpdateStmt:
		res.IsUpdate = true
		if n.TableRefs != nil {
			res.UpdateArgs = append(res.UpdateArgs, n.TableRefs.TableRefs.Text())
		}
		if n.Where != nil {
			res.Where = append(res.Where, n.Where.Text())
		}
	case *ast.InsertStmt:
		res.IsInsert = true
		if n.Table != nil {
			res.InsertTable = append(res.InsertTable, n.Table.TableRefs.Text())
		}
		for _, k := range n.Columns {
			res.InsertClmns = append(res.InsertClmns, k.Name.String())
		}
	case *ast.GrantRoleStmt:
		res.IsGrant = true
		for _, k := range n.Roles {
			res.GrantArgs = append(res.GrantArgs, k.String())
		}
		for _, k := range n.Users {
			res.GrantUSR = append(res.GrantUSR, k.Username)
		}
	case *ast.GrantStmt:
		res.IsGrant = true
		for _, k := range n.Privs {
			res.GrantArgs = append(res.GrantArgs, mysql.Priv2Str[k.Priv])
		}
		for _, k := range n.Users {
			res.GrantUSR = append(res.GrantUSR, k.User.Username)
		}
	case *ast.RevokeRoleStmt:
		res.IsRevoke = true
		for _, k := range n.Roles {
			res.RevokeArgs = append(res.RevokeArgs, k.String())
		}
		for _, k := range n.Users {
			res.RevokeUSR = append(res.RevokeUSR, k.String())
		}
	case *ast.RevokeStmt:
		res.IsRevoke = true
		for _, k := range n.Users {
			res.RevokeUSR = append(res.RevokeUSR, k.User.String())
		}
		for _, k := range n.Privs {
			res.RevokeArgs = append(res.RevokeArgs, mysql.Priv2Str[k.Priv])
		}
	case *ast.AlterTableStmt:
		res.IsAlter = true
		res.AlterTable = append(res.AlterTable, n.Table.Text())
		for _, k := range n.Specs {
			res.AlterSpec = append(res.AlterSpec, k.Text())
		}
	case *ast.DeleteStmt:
		res.IsDelete = true
		res.Where = append(res.Where, n.Where.Text())
		for _, k := range n.Tables.Tables {
			res.DeleteTable = append(res.DeleteTable, k.Text())
		}
	}

	return in, false
}

func (v *queryFields) Leave(in ast.Node) (ast.Node, bool) {
	return in, true
}

func parse(sql string) (*ast.StmtNode, error) {
	p := parser.New()
	stmtNodes, _, err := p.Parse(sql, "", "")
	if err != nil {
		return nil, err
	}

	return &stmtNodes[0], nil
}

func extract(rootNode *ast.StmtNode) *queryFields {
	v := &queryFields{}
	(*rootNode).Accept(v)
	return v
}
