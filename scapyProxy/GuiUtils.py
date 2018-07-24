from Tkinter import *
from ttk import Notebook


class VerticalScrolledFrame(Frame):
	#https://gist.github.com/EugeneBakin/76c8f9bcec5b390e45df
    """A pure Tkinter scrollable frame that actually works!
    * Use the 'interior' attribute to place widgets inside the scrollable frame
    * Construct and pack/place/grid normally
    * This frame only allows vertical scrolling
    * SET self.interior to parent!
    """
    def __init__(self, parent, *args, **kw):
        Frame.__init__(self, parent, *args, **kw)

        # create a canvas object and a vertical scrollbar for scrolling it
        self.vscrollbar = Scrollbar(self, orient=VERTICAL)
        self.vscrollbar.pack(fill=Y, side=RIGHT, expand=FALSE)
        self.canvas = Canvas(self, bd=0, highlightthickness=0, height=400,width=700,
                        yscrollcommand=self.vscrollbar.set, scrollregion=(0,0,400,700))
        self.canvas.pack(side=LEFT, fill=BOTH, expand=TRUE)
        self.vscrollbar.config(command=self.canvas.yview)

        # reset the view
        self.canvas.xview_moveto(0)
        self.canvas.yview_moveto(0)

        # create a frame inside the canvas which will be scrolled with it
        self.interior = Frame(self.canvas, height=50, width=120)
        self.interior_id = self.canvas.create_window(0, 0, window=self.interior, anchor=NW)

        # track changes to the canvas and frame width and sync them,
        # also updating the scrollbar
        def _configure_interior(event):
            # update the scrollbars to match the size of the inner frame
            size = (self.interior.winfo_reqwidth(), self.interior.winfo_reqheight())
            self.canvas.config(scrollregion="0 0 %s %s" % size)
            if self.interior.winfo_reqwidth() != self.canvas.winfo_width():
                # update the canvas's width to fit the inner frame
                self.canvas.config(width=self.interior.winfo_reqwidth())
        self.interior.bind('<Configure>', _configure_interior)

        def _configure_canvas(event):
            try:
                if self.interior.winfo_reqwidth() != self.canvas.winfo_width():
                    # update the inner frame's width to fill the canvas
                    self.canvas.itemconfigure(self.interior_id, width=self.canvas.winfo_width())
            except Exception as e:
                print '_configure_canvas err:',e
        self.canvas.bind('<Configure>', _configure_canvas)



