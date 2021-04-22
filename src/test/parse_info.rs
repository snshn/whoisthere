//  ██████╗  █████╗ ███████╗███████╗██╗███╗   ██╗ ██████╗
//  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║████╗  ██║██╔════╝
//  ██████╔╝███████║███████╗███████╗██║██╔██╗ ██║██║  ███╗
//  ██╔═══╝ ██╔══██║╚════██║╚════██║██║██║╚██╗██║██║   ██║
//  ██║     ██║  ██║███████║███████║██║██║ ╚████║╚██████╔╝
//  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

#[cfg(test)]
mod passing {
    use crate as whoisthere;

    #[test]
    fn pidesign_dot_co_dot_uk() {
        let real_domain_name = "pidesign.co.uk";
        let real_whois_response = "\

    Domain name:
        pidesign.co.uk

    Data validation:
        Nominet was able to match the registrant's name and address against a 3rd party data source on 13-Jun-2014

    Registrar:
        Paragon Internet Group Ltd t/a Tsohost [Tag = UKWEBHOSTING]
        URL: http://www.tsohost.co.uk

    Relevant dates:
        Registered on: 14-May-1998
        Expiry date:  14-May-2022
        Last updated:  14-May-2020

    Registration status:
        Registered until expiry date.

    Name servers:
        kip.ns.cloudflare.com
        uma.ns.cloudflare.com

    WHOIS lookup made at 07:59:17 10-Feb-2021

--
This WHOIS information is provided for free by Nominet UK the central registry
for .uk domain names. This information and the .uk WHOIS are:

    Copyright Nominet UK 1996 - 2021.

You may not access the .uk WHOIS or use any data from it except as permitted
by the terms of use available in full at https://www.nominet.uk/whoisterms,
which includes restrictions on: (A) use of the data for advertising, or its
repackaging, recompilation, redistribution or reuse (B) obscuring, removing
or hiding any or all of this notice and (C) exceeding query rate or volume
limits. The data is provided on an 'as-is' basis and may lag behind the
register. Access may be withdrawn or restricted at any time.
";
        let domain_props = whoisthere::parse_info(real_domain_name, real_whois_response);
        assert_eq!(domain_props.domain_name, "pidesign.co.uk");
        assert_eq!(domain_props.expiration_date, "2022-05-14T00:00:00Z");
        assert_eq!(domain_props.is_registered, true);
        assert_eq!(domain_props.is_under_grace_period, false);
    }

    #[test]
    fn crates_dot_io() {
        let real_domain_name = "crates.io";
        let real_whois_response = "\
Domain Name: CRATES.IO
Registry Domain ID: D503300000040513565-LRMS
Registrar WHOIS Server: whois.gandi.net
Registrar URL: https://www.gandi.net/whois
Updated Date: 2020-08-13T16:28:56Z
Creation Date: 2014-01-22T08:28:29Z
Registry Expiry Date: 2023-01-22T08:28:29Z
Registrar Registration Expiration Date:
Registrar: Gandi SAS
Registrar IANA ID: 81
Registrar Abuse Contact Email: abuse@support.gandi.net
Registrar Abuse Contact Phone: +33.170377661
Reseller:
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Organization:
Registrant State/Province: OR
Registrant Country: US
Name Server: NS-1543.AWSDNS-00.CO.UK
Name Server: NS-217.AWSDNS-27.COM
Name Server: NS-1064.AWSDNS-05.ORG
Name Server: NS-817.AWSDNS-38.NET
DNSSEC: unsigned

>>> Last update of WHOIS database: 2021-02-09T22:05:38Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

Access to WHOIS information provided by Internet Computer Bureau Ltd. ICB is provided to assist persons in determining the contents of a domain name registration record in the ICB registry database. The data in this record is provided by ICB for informational purposes only, and ICB does not guarantee its accuracy. This service is intended only for query-based access. You agree that you will use this data only for lawful purposes and that, under no circumstances will you use this data to(i) allow, enable, or otherwise support the transmission by e-mail, telephone, facsimile or other electronic means of mass, unsolicited, commercial advertising or solicitations to entities other than the data recipient's own existing customers; or (ii) enable high volume, automated, electronic processes that send queries or data to the systems of Registry Operator, a Registrar, or ICB or its services providers except as reasonably necessary to register domain names or modify existing registrations. UK privacy laws limit the scope of information permitted for certain public access.  Therefore, concerns regarding abusive use of domain registrations in the ICB registry should be directed to either (a) the Registrar of Record as indicated in the WHOIS output, or (b) the ICB anti-abuse department at abuse@icbregistry.info.

All rights reserved. ICB reserves the right to modify these terms at any time. By submitting this query, you agree to abide by these policies
";
        let domain_props = whoisthere::parse_info(real_domain_name, real_whois_response);
        assert_eq!(domain_props.domain_name, "crates.io");
        assert_eq!(domain_props.expiration_date, "2023-01-22T08:28:29Z");
        assert_eq!(domain_props.is_registered, true);
        assert_eq!(domain_props.is_under_grace_period, false);
    }

    #[test]
    fn site_dot_is() {
        let real_domain_name = "site.is";
        let real_whois_response = "\
% This is the ISNIC Whois server.
%
% Rights restricted by copyright.
% See https://www.isnic.is/en/about/copyright

domain:       site.is
registrant:   ES5722-IS
admin-c:      ES206-IS
tech-c:       ES206-IS
zone-c:       JQ9-IS
billing-c:    ES206-IS
nserver:      cdns1.interserver.net
nserver:      cdns2.interserver.net
nserver:      cdns3.interserver.net
dnssec:       unsigned delegation
created:      March 14 2013
expires:      March 14 2021
source:       ISNIC

nic-hdl:      ES5722-IS
address:      IS
created:      March 14 2013
source:       ISNIC

nic-hdl:      ES206-IS
address:      IS
created:      December 16 2010
source:       ISNIC

nic-hdl:      JQ9-IS
address:      US
created:      March 15 2017
source:       ISNIC
";
        let domain_props = whoisthere::parse_info(real_domain_name, real_whois_response);
        assert_eq!(domain_props.domain_name, "site.is");
        assert_eq!(domain_props.expiration_date, "2021-03-14T00:00:00Z");
        assert_eq!(domain_props.is_registered, true);
        assert_eq!(domain_props.is_under_grace_period, false);
    }
}

//  ███████╗ █████╗ ██╗██╗     ██╗███╗   ██╗ ██████╗
//  ██╔════╝██╔══██╗██║██║     ██║████╗  ██║██╔════╝
//  █████╗  ███████║██║██║     ██║██╔██╗ ██║██║  ███╗
//  ██╔══╝  ██╔══██║██║██║     ██║██║╚██╗██║██║   ██║
//  ██║     ██║  ██║██║███████╗██║██║ ╚████║╚██████╔╝
//  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝╚═╝  ╚═══╝ ╚═════╝

#[cfg(test)]
mod failing {
    use crate as whoisthere;

    #[test]
    fn unregistered_dot_gov() {
        let mock_domain_name = "unregistered.gov";
        let mock_whois_response = "\
% DOTGOV WHOIS Server ready
No match for \"UNREGISTERED.GOV\".
>>> Last update of whois database: 2021-02-02T10:32:47Z <<<

Please be advised that this whois server only contains information pertaining
to the .GOV domain. For information for other domains please use the whois
server at RS.INTERNIC.NET.
";
        let domain_props = whoisthere::parse_info(mock_domain_name, mock_whois_response);
        assert_eq!(domain_props.domain_name, "unregistered.gov");
        assert_eq!(domain_props.expiration_date, "");
        assert_eq!(domain_props.is_registered, false);
        assert_eq!(domain_props.is_under_grace_period, false);
    }

    #[test]
    fn unregistered_dot_social() {
        let mock_domain_name = "unregistered.social";
        let mock_whois_response = "\
Domain not found.

Terms of Use: Donuts Inc. provides this Whois service for information purposes, and to assist persons in obtaining information about or related to a domain name registration record. Donuts does not guarantee its accuracy. Users accessing the Donuts Whois service agree to use the data only for lawful purposes, and under no circumstances may this data be used to: a) allow, enable, or otherwise support the transmission by e-mail, telephone, or facsimile of mass unsolicited, commercial advertising or solicitations to entities other than the registrar’s own existing customers and b) enable high volume, automated, electronic processes that send queries or data to the systems of Donuts or any ICANN-accredited registrar, except as reasonably necessary to register domain names or modify existing registrations. When using the Donuts Whois service, please consider the following: The Whois service is not a replacement for standard EPP commands to the SRS service. Whois is not considered authoritative for registered domain objects. The Whois service may be scheduled for downtime during production or OT&E maintenance periods. Queries to the Whois services are throttled. If too many queries are received from a single IP address within a specified time, the service will begin to reject further queries for a period of time to prevent disruption of Whois service access. Abuse of the Whois system through data mining is mitigated by detecting and limiting bulk query access from single sources. Where applicable, the presence of a [Non-Public Data] tag indicates that such data is not made publicly available due to applicable data privacy laws or requirements. Should you wish to contact the registrant, please refer to the Whois records available through the registrar URL listed above. Access to non-public data may be provided, upon request, where it can be reasonably confirmed that the requester holds a specific legitimate interest and a proper legal basis for accessing the withheld da
ta. Access to this data can be requested by submitting a request via the form found at https://donuts.domains/about/policies/whois-layered-access/ Donuts Inc. reserves the right to modify these terms at any time. By submitting this query, you agree to abide by this policy.
";
        let domain_props = whoisthere::parse_info(mock_domain_name, mock_whois_response);
        assert_eq!(domain_props.domain_name, "unregistered.social");
        assert_eq!(domain_props.expiration_date, "");
        assert_eq!(domain_props.is_registered, false);
        assert_eq!(domain_props.is_under_grace_period, false);
    }

    #[test]
    fn unregistered_dot_is() {
        let mock_domain_name = "unregistered.is";
        let mock_whois_response = "\
% This is the ISNIC Whois server.
%
% Rights restricted by copyright.
% See https://www.isnic.is/en/about/copyright

%
% No entries found for query \"unregistered.is\".
";
        let domain_props = whoisthere::parse_info(mock_domain_name, mock_whois_response);
        assert_eq!(domain_props.domain_name, "unregistered.is");
        assert_eq!(domain_props.expiration_date, "");
        assert_eq!(domain_props.is_registered, false);
        assert_eq!(domain_props.is_under_grace_period, false);
    }
}
