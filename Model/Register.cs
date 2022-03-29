using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace FingerTip_MobileApp.Model
{
    public class Register
    {
        [Required(ErrorMessage ="*Username is required")]
        public string username { get; set; }
        [Required(ErrorMessage = "*Email is required")]
        public string email { get; set; }
        [Required(ErrorMessage = "*Password is required")]
        public string password { get; set; }
        [Required(ErrorMessage = "*Confirm Password is required")]
        [Compare(nameof(password), ErrorMessage ="*Password should match with Confirm Password")]
        public string confirmPassword { get; set; }
    }
}
