using SQLite;

namespace Server.Database.Entities
{
    [Table("Account")]
    public class Account
    {
        [AutoIncrement, PrimaryKey]
        public int Id { get; set; }

        [MaxLength(64)]
        public string Username { get; set; }

        [MaxLength(64), Unique]
        public string Email { get; set; }

        [MaxLength(128)]
        public byte[] PasswordHash { get; set; }
        
        [MaxLength(128)]
        public byte[] PasswordSalt { get; set; }
    }
}