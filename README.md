# Wireless Probe Requests

Wireless Probe Requests are an essential part of Wi-Fi communication. They play a crucial role in the process of discovering and connecting to wireless networks. In this detailed explanation, will be shown what wireless probe requests are, how they work, and their significance in Wi-Fi networks.

### Wireless Probe Request: An Overview

Wireless Probe Requests are management frames used by Wi-Fi devices (such as laptops, smartphones, and IoT devices) to discover nearby wireless networks. These requests are broadcasted by the client devices, and they serve as a way for devices to find available Wi-Fi networks to connect to.

### Key Elements of a Wireless Probe Request:

 * SSID (Service Set Identifier): The SSID is the name of the Wi-Fi network the device is trying to discover or connect to. This field can be empty or contain the SSID of a specific network;
 * BSSID (Basic Service Set Identifier): The BSSID is the MAC address of the access point (AP) or router that the device is probing. If the device is trying to connect to a specific network, it will include the BSSID of that network's AP;
 * Additional Information: Probe requests may contain additional information such as the supported Wi-Fi standards (e.g., 802.11ac, 802.11n), the device's capabilities, and more.

### How Wireless Probe Requests Work:

> [!NOTE]
> **Initiation**: When a Wi-Fi device is powered on or its wireless interface is enabled, it initiates a scanning process to discover nearby networks. This process begins with the device sending out one or more probe requests.
>
> **Broadcast**: The probe request is broadcasted, meaning it is sent to all access points within range of the device. This is important because the device doesn't yet know which access points are available.
>
> **AP Responses**: Access points within range that receive the probe request may respond with a Probe Response frame. These responses typically contain information about the AP's capabilities, security settings, and, most importantly, the SSID.
>
> **SSID Collection**: The device collects these Probe Responses and uses the information to build a list of available networks, along with their signal strength, security, and other relevant details.
>
> **User Interaction**: The device may then present this list to the user through a Wi-Fi management interface (e.g., on a smartphone or laptop), allowing the user to select a network to connect to.
>
> **Connection**: Once the user selects a network, the device sends an association request to the chosen AP, initiating the process of connecting to the network.


### Significance of Wireless Probe Requests:
 **Network Discovery**: Probe requests are the first step in discovering available Wi-Fi networks. They allow devices to find networks even when they don't know the SSID in advance.
 
 **Efficient Scanning**: Devices can use probe requests to efficiently scan for networks by sending out specific requests only for the SSIDs they are interested in, conserving power.
 
 **User Interaction**: Probe requests facilitate user-friendly network selection interfaces, making it easy for users to connect to desired networks.
 
 **Security Implications**: While necessary for network discovery, probe requests can also be used for malicious purposes, such as tracking or profiling user behavior. This has led to privacy concerns and countermeasures like MAC address randomization.

#### In summary, wireless probe requests are fundamental to the operation of Wi-Fi networks, allowing devices to discover and connect to available networks efficiently. They are a crucial part of the initial handshake between client devices and access points.
----

# WifiProbe
 
### Usage:

```
Get the interface name:

localmachine:~# ifconfig -a
localmachine:~# ifconfig <interface-name> down
localmachine:~# iwconfig <interface-name> mode monitor
localmachine:~# ifconfig <interface-name> up
localmachine:~# python3 script.py 

```

> Highlights information that users should take into account, even when skimming.

> [!IMPORTANT]
> Crucial information necessary for users to succeed.

> [!WARNING]
> Critical content demanding immediate user attention due to potential risks.
