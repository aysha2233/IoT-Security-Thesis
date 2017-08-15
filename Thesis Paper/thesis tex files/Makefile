RM	=	rm

PDFLATEXSW = -shell-escape

BASE    =       main

all:
	pdflatex $(PDFLATEXSW) $(BASE)
	-bibtex $(BASE)
	pdflatex $(PDFLATEXSW) $(BASE)
	pdflatex $(PDFLATEXSW) $(BASE)
	$(RM) -f *.ilg *.log *.dvi *.bbl *.aux *.blg *.X??? *.out *.ps *.gz

once:
	pdflatex $(PDFLATEXSW) $(BASE)
	

clean:
	$(RM) -f *.ilg *.log *.dvi *.bbl *.aux *.blg *.X??? *.out *.ps *.gz $(BASE).pdf 
