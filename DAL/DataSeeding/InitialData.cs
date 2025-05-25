using System.Net.Mime;

namespace DAL.DataSeeding;

public class InitialData
{
    public static readonly (string roleName, Guid? id)[]
        Roles =
        [
            ("Admin", null),
            ("User", null),
            
        ];
    
    public static readonly (string email, string firstName, string lastName, string password, Guid? id, string[] roles)[]
        Users =
        [
            ("danil@dainlar.ee", "Danil", "Zimarev", "Foobar1.", null, ["Admin"]),
            ("user2@quizmastery.com", "Test", "User2", "Password.2", null, ["User"])
        ];
    
    
}