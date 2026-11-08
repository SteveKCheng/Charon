using Charon;

var builder = WebApplication.CreateSlimBuilder(args);
var options = CharonOptions.Load(builder.Configuration);
CharonApp.Build(builder, options).Run();
