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

#ifndef WHB_ICMP_HELPER_H
#define WHB_ICMP_HELPER_H

#include "ns3/node-container.h"
#include "ns3/application-container.h"
#include "ns3/object-factory.h"

namespace ns3 {

/**
 * \ingroup whb_icmp
 * \brief Create a whb_icmp application and associate it to a node
 *
 * This class creates one or multiple instances of ns3::whb_icmp and associates
 * it/them to one/multiple node(s).
 */
class whb_icmpHelper
{
public:
  /**
   * Create a whb_icmpHelper which is used to make life easier for people wanting
   * to use whb_icmp Applications.
   *
   * \param remote The address which should be TODO
   */
  whb_icmpHelper (Ipv4Address remote);

  /**
   * Install a Ping application on each Node in the provided NodeContainer.
   *
   * \param nodes The NodeContainer containing all of the nodes to get a whb_icmp
   *              application.
   *
   * \returns A list of whb_icmp applications, one for each input node
   */
  ApplicationContainer Install (NodeContainer nodes) const;

  /**
   * Install a whb_icmp application on the provided Node.  The Node is specified
   * directly by a Ptr<Node>
   *
   * \param node The node to install the whb_icmpApplication on.
   *
   * \returns An ApplicationContainer holding the Ping application created.
   */
  ApplicationContainer Install (Ptr<Node> node) const;

  /**
   * Install a Ping application on the provided Node.  The Node is specified
   * by a string that must have previously been associated with a Node using the
   * Object Name Service.
   *
   * \param nodeName The node to install the whb_icmpApplication on.
   *
   * \returns An ApplicationContainer holding the whb_icmp application created.
   */
  ApplicationContainer Install (std::string nodeName) const;

  /**
   * \brief Configure whb_icmp applications attribute
   * \param name   attribute name
   * \param value  attribute value
   */
  void SetAttribute (std::string name, const AttributeValue &value);
private:
  /**
   * \brief Do the actual application installation in the node
   * \param node the node
   * \returns a Smart pointer to the installed application
   */
  Ptr<Application> InstallPriv (Ptr<Node> node) const;
  /// Object factory
  ObjectFactory m_factory;
};

} // namespace ns3

#endif /* WHB_ICMP_HELPER_H */