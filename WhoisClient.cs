using Penguin.Extensions.String;
using Penguin.Net.Telnet;
using Penguin.Net.Whois.Objects;
using Penguin.Services.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Penguin.Net.Whois
{
    /// <summary>
    /// A thin Whois client
    /// </summary>
    public class WhoisClient : Service
    {
        #region Methods

        /// <summary>
        /// The query to send to the server chain. Likely wont work reliably with flags.
        /// </summary>
        /// <param name="QueryString">The Host or IP to query for</param>
        /// <returns>A collection of data from the server chain</returns>
        public QueryResponse Query(string QueryString)
        {
            QueryResponse queryResponse = new QueryResponse();

            string whoisServer = "whois.arin.net";

            string response = string.Empty;

            bool requery = false;

            do
            {
                if (!discoveredServers.Contains(whoisServer))
                {
                    discoveredServers.Add(whoisServer);
                }

                requery = false;

                TelnetClient client;

                try
                {
                    if (whoisServer.Contains(":"))
                    {
                        client = new TelnetClient(whoisServer.To(":"), int.Parse(whoisServer.From(":")));
                    }
                    else
                    {
                        client = new TelnetClient(whoisServer, 43);
                    }

                    response = client.Send(QueryString);
                }
                catch (Exception ex)
                {
                    this.Error?.Invoke(ex);
                    return queryResponse;
                }

                queryResponse.ServerResponses.Add(new ServerResponse()
                {
                    Response = response,
                    Server = whoisServer,
                    Request = QueryString
                });

                if (response.Contains(REFERRAL_SERVER))
                {
                    requery = true;

                    whoisServer = response.Split('\n').First(s => s.Contains(REFERRAL_SERVER)).From(": ");

                    if (whoisServer.Contains("://"))
                    {
                        whoisServer = whoisServer.From("://");
                    }
                }
            } while (requery);

            WhoisResponse whoisResponse = new WhoisResponse();

            foreach (string s in response.Split('\n'))
            {
                string toParse = s;

                if (toParse.StartsWith("#") || toParse.StartsWith("%") || string.IsNullOrWhiteSpace(toParse))
                {
                    continue;
                }

                Match m = Regex.Match(s, @"(.+)\s(.+)\s(\(.+\))\s([0-9\.]*)\s+-\s+([0-9\.]*)");

                if (m.Success)
                {
                    WhoisResponse thisResponse = new WhoisResponse();

                    thisResponse.OrgName = m.Groups[1].Value;
                    thisResponse.NetName = m.Groups[2].Value;
                    thisResponse.IPFrom = m.Groups[4].Value;
                    thisResponse.IPTo = m.Groups[5].Value;

                    queryResponse.WhoisResponses.Add(thisResponse);
                    continue;
                }

                if (!toParse.Contains(":"))
                {
                    continue;
                }

                if (toParse.StartsWith("network:"))
                {
                    toParse = toParse.From(":");
                }

                string key = toParse.To(":").Trim().ToLower();
                string Value = toParse.From(":").Trim();

                //wayport

                switch (key)
                {
                    case "inetnum":
                    case "netrange":
                    case "ip-network-block":
                    case "cidr":
                    case "ip-network":
                        if (Value.Contains("-"))
                        {
                            whoisResponse.IPFrom = Value.To("-").Trim();
                            whoisResponse.IPTo = Value.From("-").Trim();
                        }
                        else if (Value.Contains("/"))
                        {
                            whoisResponse.CIDR = string.IsNullOrWhiteSpace(whoisResponse.Country) ? Value : $"{Value}, {whoisResponse.CIDR}";
                        }
                        else
                        {
                            throw new Exception("Invalid network");
                        }

                        break;

                    case "netname":
                    case "network-name":
                        whoisResponse.NetName = Value;
                        break;

                    case "country":
                    case "country-code":
                        whoisResponse.Country = string.IsNullOrWhiteSpace(whoisResponse.Country) ? Value : whoisResponse.Country;
                        break;

                    case "org-name":
                    case "orgname":
                    case "organization;i":
                        whoisResponse.OrgName = Value;
                        break;
                }
            }

            //Make sure we have something to return
            if (!string.IsNullOrWhiteSpace(whoisResponse.CIDR) || !string.IsNullOrWhiteSpace(whoisResponse.IPFrom))
            {
                queryResponse.WhoisResponses.Add(whoisResponse);
            }

            return queryResponse;
        }

        #endregion Methods

        #region Fields

        private const string REFERRAL_SERVER = "ReferralServer: ";

        private static HashSet<string> discoveredServers = new HashSet<string>();

        #endregion Fields
    }
}