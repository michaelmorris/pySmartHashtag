# pySmartHashtag

This is a proof of concept experimental fork of pySmartHashtag by Bastian Neumann to make it compatible with Volvo EX30 cars.

The Volvo EX30 is a geely platform car just like the Smart #1 and #3, and as it turns out has a seemingly identical API to those cars, but uses a different identity provider to initially log in to geely's platform (the Volvo ID service).

The current status of this code is that it appears to work via the CLI. It may infact support some functions not available in the official EX30 app (requests to enable the seat heaters appear to work, which is not possible in the EX30 app - the API appears to report that it worked, but I haven't been able to confirm the heaters actually physically turning on yet, its too hot where I am to tell currently). It will not work with the accompanying home assistant plugin at this stage as the volvo identity API requires an interactive authentication process (it needs the user to enter an OTP code that is emailed to them) and the plugin does not support that. I may in the future similarly fork the home assistant plugin to make it work with this, but I can give no promises at this point.

I've tried to keep the code compatible with both Smart cars and the EX30, but as I don't have a Smart car to test it with its likely currently broken.

This is mostly for my own experimentation at this point. The changes I've made to the code are pretty rough, both because I'm simply using it for experiments and because I'm not a python dev. Please do not expect any ongoing support or development at this point, or any further work at all - I do not know if I have the time to commit for that, and I do not know if Bastian has any intention of using any of this work. That said, please do feel free to use this work as a base - I have put this on github for the purpose of sharing what I've found.