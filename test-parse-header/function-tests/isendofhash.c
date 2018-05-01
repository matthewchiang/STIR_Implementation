
int isendofhash (char* p, char* end)
{
	/* new header line */
	if ((p<end && *p==';')
		/* end of message */
		|| ((*p=='\n' || *p=='\r') && p+1==end))
		return 1;
	else
		return 0;
}