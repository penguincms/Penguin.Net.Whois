using System.Collections.Generic;

namespace Penguin.Net.Whois.Objects
{
    /// <summary>
    /// A collection of information generated while querying the whois chain
    /// </summary>
    public class QueryResponse
    {
        #region Properties

        /// <summary>
        /// Raw responses from the servers
        /// </summary>
        public List<ServerResponse> ServerResponses { get; set; } = new List<ServerResponse>();

        /// <summary>
        /// Parsed information from the raw responses
        /// </summary>
        public List<WhoisResponse> WhoisResponses { get; set; } = new List<WhoisResponse>();

        #endregion Properties
    }
}