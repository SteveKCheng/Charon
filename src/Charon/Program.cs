using Charon;

var builder = WebApplication.CreateSlimBuilder(args);
var options = builder.Configuration.GetSection("Charon").Get<CharonOptions>() ?? new CharonOptions();
CharonApp.Build(builder, options).Run();
