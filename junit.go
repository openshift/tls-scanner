package main

import "encoding/xml"

// JUnitTestSuite is a collection of test cases.
type JUnitTestSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Time       float64         `xml:"time,attr"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase is a single test case.
type JUnitTestCase struct {
	XMLName   xml.Name      `xml:"testcase"`
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      float64       `xml:"time,attr"`
	Failure   *JUnitFailure `xml:"failure,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
	SystemErr string        `xml:"system-err,omitempty"`
}

// JUnitFailure contains the failure details of a test case.
type JUnitFailure struct {
	XMLName xml.Name `xml:"failure"`
	Message string   `xml:"message,attr"`
	Type    string   `xml:"type,attr"`
	Content string   `xml:",chardata"`
}

// JUnitProperty represents a key-value pair.
type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}
