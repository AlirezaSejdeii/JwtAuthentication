using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtAuthentication.Models.Context
{
    public class JwtContext: IdentityDbContext
    {
        public JwtContext(DbContextOptions<JwtContext> options):base(options)
        {}
    }
}
