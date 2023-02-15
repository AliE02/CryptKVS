# How to run the generated test case ?

You'll find in each subfolder a script named `run.sh`, that can run your executable to reproduce the crash.
You must have compiled your binary before running it, then you can just type:
```
cd <crash-folder>
bash ./run.sh
```

The original crash report was dumped to `crash_output.txt`.
Also note that the name of the folder may not correspond to the type of crash you're having, this is related to how test cases are generated.

**Important:** The binary should have been compiled with `-fsanitize=address` at the very least. 
If you don't manage to reproduce the crash, it may be because you're missing a sanitizer,
so try to recompile with `-fsanitize=address,leak,undefined,integer`.

You can check out the scripts if you wish, they are quite simple: 
they only export the required environment variables and run the binaries.

Lastly, note that this is purely optional - you may use this to make your project more robust, 
or you may ignore it if you don't have the will or time to exploit it.
