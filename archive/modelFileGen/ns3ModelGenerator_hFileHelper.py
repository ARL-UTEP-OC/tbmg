#!/usr/bin/python
#Creates a C++ NS-3 Model Using python
from bs4 import BeautifulSoup
from jinja2 import Template
import sys

xmlFilename = sys.argv[1]
modelName = sys.argv[2]

soup = BeautifulSoup(open(xmlFilename,'r'), 'xml')

def generateFile(filename):
	hFileHelper = Template('''
/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2008 INRIA
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#ifndef {{jinjaModelName|upper}}_HELPER_H
#define {{jinjaModelName|upper}}_HELPER_H

#include "ns3/node-container.h"
#include "ns3/application-container.h"
#include "ns3/object-factory.h"

namespace ns3 {

/**
 * \\ingroup {{jinjaModelName}}
 * \\brief Create a {{jinjaModelName}} application and associate it to a node
 *
 * This class creates one or multiple instances of ns3::{{jinjaModelName}} and associates
 * it/them to one/multiple node(s).
 */
class {{jinjaModelName}}Helper
{
public:
  /**
   * Create a {{jinjaModelName}}Helper which is used to make life easier for people wanting
   * to use {{jinjaModelName}} Applications.
   *
   * \\param remote The address which should be {{todo}}
   */
  {{jinjaModelName}}Helper (Ipv4Address remote);

  /**
   * Install a Ping application on each Node in the provided NodeContainer.
   *
   * \\param nodes The NodeContainer containing all of the nodes to get a {{jinjaModelName}}
   *              application.
   *
   * \\returns A list of {{jinjaModelName}} applications, one for each input node
   */
  ApplicationContainer Install (NodeContainer nodes) const;

  /**
   * Install a {{jinjaModelName}} application on the provided Node.  The Node is specified
   * directly by a Ptr<Node>
   *
   * \\param node The node to install the {{jinjaModelName}}Application on.
   *
   * \\returns An ApplicationContainer holding the Ping application created.
   */
  ApplicationContainer Install (Ptr<Node> node) const;

  /**
   * Install a Ping application on the provided Node.  The Node is specified
   * by a string that must have previously been associated with a Node using the
   * Object Name Service.
   *
   * \\param nodeName The node to install the {{jinjaModelName}}Application on.
   *
   * \\returns An ApplicationContainer holding the {{jinjaModelName}} application created.
   */
  ApplicationContainer Install (std::string nodeName) const;

  /**
   * \\brief Configure {{jinjaModelName}} applications attribute
   * \\param name   attribute's name
   * \\param value  attribute's value
   */
  void SetAttribute (std::string name, const AttributeValue &value);
private:
  /**
   * \\brief Do the actual application installation in the node
   * \\param node the node
   * \\returns a Smart pointer to the installed application
   */
  Ptr<Application> InstallPriv (Ptr<Node> node) const;
  /// Object factory
  ObjectFactory m_factory;
};

} // namespace ns3

#endif /* {{jinjaModelName|upper}}_HELPER_H */
''')
	ofile = open(filename, 'w')
	ofile.write(hFileHelper.render(jinjaModelName=modelName, todo='TODO'))
	#print hFileHelper.render(jinjaPacketType=mid, jinjaModelName=modelName, jinjaFieldNames=myFieldNames, todo='TODO', defaultDataType='char')

def calcStrOr(smaller, smallerNumBytes, larger, largerNumBytes):
	numBytesDiff = largerNumBytes-smallerNumBytes
	largerBase16 = int(larger,16)
	smallerBase16 = int(smaller,16) << (8*numBytesDiff)
	 
	return (hex(largerBase16 | smallerBase16))[2:]

def main():
	outputPath = modelName+"/"+modelName+"model/"
	generateFile(outputPath+modelName+"-helper.h")
if __name__ == "__main__":
	main()
