Traffic Analysis Tool logs all network traffic and exports to a created excel file. The log will have columns for port, packet details, and other information.
You can modify the string to export CSV if you are utilizing Linux. 

You will need to update lines 71 and 72 to the below.

output_file = f"networktraffic_log_{timestamp}.csv"
df.to_csv(output_file, index=False)

I will next try to create a executable which will accept manual prompt to stop sniffing.
