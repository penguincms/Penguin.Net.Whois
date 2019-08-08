namespace Penguin.Net.Whois.Objects
{
    /// <summary>
    /// A basic encapsulation of common query response fields
    /// </summary>
    public class WhoisResponse
    {
        #region Properties

        /// <summary>
        /// A CSV list of CIDR addresses found when querying
        /// </summary>
        public string CIDR { get; set; }

        /// <summary>
        /// The country the range is registered in
        /// </summary>
        public string Country { get; set; }

        /// <summary>
        /// The start of the range in this block
        /// </summary>
        public string IPFrom { get; set; }

        /// <summary>
        /// The end of the range in this block
        /// </summary>
        public string IPTo { get; set; }

        /// <summary>
        /// The name for this particular block of addresses
        /// </summary>
        public string NetName { get; set; }

        /// <summary>
        /// The organization name that registered the block/IP
        /// </summary>
        public string OrgName { get; set; }

        #endregion Properties
    }
}